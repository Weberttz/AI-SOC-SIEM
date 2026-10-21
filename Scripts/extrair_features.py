"""O script Python lerá o JSON unificado e irá aplicar técnicas de tratamento de dados dependendo do tipo de cada campo:
1. Variáveis Numéricas (Portas, Tamanho do Pacote): Mantêm-se numéricas, mas geralmente aplicamos uma normalização (colocar os valores entre 0 e 1) para que uma porta alta (ex: 54321) não distorça o peso do modelo frente a uma porta baixa (ex: 80).
2. Variáveis Categóricas/Texto (Protocolo, Tipo de Alerta): Modelos não leem "TCP" ou "UDP". Usamos técnicas como One-Hot Encoding (criar colunas binárias de 0 e 1 para cada opção) ou Label Encoding (atribuir um número para cada categoria).
3. Timestamps (Data e Hora): O modelo não entende "2026-10-20T14:00:00Z". Extraímos características numéricas dele, como: Hora do dia (0 a 23), Dia da semana (0 a 6) ou se é Fim de semana (0 ou 1).
4. Endereços IP: Não devem ser convertidos diretamente em número decimal puro. Geralmente, extraímos características deles (ex: O IP é interno ou externo?, Está em uma lista de IPs bloqueados? ou aplicamos técnicas de contagem de frequência)."
"""

import pandas as pd
import json 
from sklearn.preprocessing import MinMaxScaler
from pathlib import Path

raiz_do_projeto = Path(__file__).resolve().parent.parent
caminho_destino = raiz_do_projeto / "Dados" / "dados.json"
caminho_arquivo = raiz_do_projeto / "Logs_unificados/unificado.jsonl"
eventos = []

"""ESQUEMA = [
    "timestamp",        # UTC, ISO8601
    "source_tool",      # suricata | zeek | wazuh | cowrie | dionaea | heralding
    "event_type",       # alert, flow, auth, session, command...
    "src_ip", "src_port", "dst_ip", "dst_port",
    "proto",            # transporte: tcp/udp/icmp (minúsculo)
    "app_proto",        # aplicação: http, ssh, dns...
    "severity",         # normalizada: info | low | medium | high | critical
    "severity_orig",    # valor original da ferramenta
    "signature",        # nome da regra/assinatura/descrição
    "signature_id",
    "category",
    "session_id",       # flow_id (suricata), uid (zeek), session (cowrie)...
    "username", "password",
    "payload",          # comando (cowrie), URL/hash (dionaea), etc.
    "pkts_to_server", "pkts_to_client",
    "bytes_to_server", "bytes_to_client",
    "duration_s",
    "agent_name",       # wazuh: agente que coletou
    "src_log",          # arquivo de origem
    "extra",            # JSON com campos específicos da ferramenta
]"""

with open(caminho_arquivo) as arquivo:
    for linha in arquivo:
           if not linha.strip():
               continue
   
           try:
               evento = json.loads(linha)
               eventos.append(evento)
           except json.JSONDecodeError:
               print("Linha JSON inválida encontrada.")
               continue

# 1. Simulação dos dados que saíram do seu JSON unificado
dados_json = eventos

# Converter a lista de JSONs para um DataFrame do Pandas (formato tabular)
df = pd.DataFrame(dados_json)

# --- PASSO 2: Tratamento do Timestamp ---
df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['day_of_week'] = df['timestamp'].dt.dayofweek
# Removemos a coluna original de timestamp pois ela não vai para o vetor final
df = df.drop(columns=['timestamp'])

""" Remover
* signature e signature_id (vão gerar colunas infinitas no dummy)
* user e senha (são textos muito aleatórios de força bruta)
* payload (comandos e URLs mto longos q talvez quebrem o modelo por n conseguir processar)
* session_id (é só um id único, pode confundir a ia)
* agent_name e src_log (se n for o msm q o source_tool, acho q tbm dá pra largar, já q é só o nome do agente e o caminho do log tbm acho q n muda o comportamento do ataque)
* extra (acho q é só o json bruto, n deve dar pra ler direito)"""

# Passando todas as colunas de uma vez só e salvando de volta no df
df = df.drop(columns=[
    'signature', 'signature_id', 'username', 'password', 'category',
    'payload', 'session_id', 'src_log', 'agent_name', 'extra'
], errors='ignore') # errors='ignore' evita que o código quebre caso alguma coluna já não exista

# --- PASSO 3: Tratamento de Variáveis Categóricas (One-Hot Encoding) ---
# Isso vai transformar a coluna 'proto' em 'proto_TCP' e 'proto_UDP' com valores 0 ou 1
# E fará o mesmo com a coluna 'source_tool'
df_encoded = pd.get_dummies(df, columns=['proto', 'source_tool', 'app_proto'], dtype=int)

CAMPOS = [
    'severity_orig', 'pkts_to_server', 'pkts_to_client', 
    'bytes_to_server', 'bytes_to_client', 'duration_s'
]

# --- PASSO 4: Normalização de Valores Numéricos (Colocar entre 0 e 1) ---
scaler = MinMaxScaler()
mapa_severidade = {'info': 0, 'low': 1, 'high': 2, 'critical': 3}

# coloca como 0 os nulls
df_encoded['severity'] = df_encoded['severity'].fillna('info')

for campo in CAMPOS:
    df_encoded[campo] = df_encoded[campo].fillna(0)

# transforma em numero
df_encoded['severity'] = df_encoded['severity'].map(mapa_severidade)

# Vamos normalizar a porta de destino e a severidade para a mesma escala
df_encoded[['src_port','dst_port','hour','day_of_week', 'severity']] = scaler.fit_transform(
    df_encoded[['src_port','dst_port','hour', 'day_of_week', 'severity']]
)

# --- PASSO 5: Gerando os Vetores de Características ---
# Cada linha da matriz resultante é um vetor numérico pronto para a IA
vetores_caracteristicas = df_encoded.to_numpy()

# Exibindo o resultado final formatado
print("=== DataFrame Estruturado (Pronto para IA) ===")
print(df_encoded)

caminho_destino.parent.mkdir(parents=True, exist_ok=True)

df_encoded.to_json(caminho_destino,orient='records', indent=4)
