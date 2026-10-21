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

# Defina a pasta de destino e o nome do arquivo
caminho_destino = Path("./Dados/dados.json")
nome_arquivo = "unificado.jsonl"
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

with open(nome_arquivo) as arquivo:
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

# --- PASSO 3: Tratamento de Variáveis Categóricas (One-Hot Encoding) ---
# Isso vai transformar a coluna 'proto' em 'proto_TCP' e 'proto_UDP' com valores 0 ou 1
# E fará o mesmo com a coluna 'source_tool'
df_encoded = pd.get_dummies(df, columns=['proto', 'source_tool', 'app_proto'], dtype=int)

# --- PASSO 4: Normalização de Valores Numéricos (Colocar entre 0 e 1) ---
scaler = MinMaxScaler()
# Vamos normalizar a porta de destino e a severidade para a mesma escala
df_encoded[['src_port','dst_port','hour','day_of_week']] = scaler.fit_transform(
    df_encoded[['src_port','dst_port','hour', 'day_of_week']]
)

# --- PASSO 5: Gerando os Vetores de Características ---
# Cada linha da matriz resultante é um vetor numérico pronto para a IA
vetores_caracteristicas = df_encoded.to_numpy()

# Exibindo o resultado final formatado
print("=== DataFrame Estruturado (Pronto para IA) ===")
print(df_encoded)

caminho_destino.parent.mkdir(parents=True, exist_ok=True)

df_encoded.to_json(caminho_destino,orient='records', indent=4)
