
"""O script Python lerá o JSON unificado e irá aplicar técnicas de tratamento de dados dependendo do tipo de cada campo:
1. Variáveis Numéricas (Portas, Tamanho do Pacote): Mantêm-se numéricas, mas geralmente aplicamos uma normalização (colocar os valores entre 0 e 1) para que uma porta alta (ex: 54321) não distorça o peso do modelo frente a uma porta baixa (ex: 80).
2. Variáveis Categóricas/Texto (Protocolo, Tipo de Alerta): Modelos não leem "TCP" ou "UDP". Usamos técnicas como One-Hot Encoding (criar colunas binárias de 0 e 1 para cada opção) ou Label Encoding (atribuir um número para cada categoria).
3. Timestamps (Data e Hora): O modelo não entende "2026-10-20T14:00:00Z". Extraímos características numéricas dele, como: Hora do dia (0 a 23), Dia da semana (0 a 6) ou se é Fim de semana (0 ou 1).
4. Endereços IP: Não devem ser convertidos diretamente em número decimal puro. Geralmente, extraímos características deles (ex: O IP é interno ou externo?, Está em uma lista de IPs bloqueados? ou aplicamos técnicas de contagem de frequência)."
"""

import pandas as pd
import json 
import argparse
import ipaddress
from sklearn.preprocessing import MinMaxScaler
from pathlib import Path

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

MAPA_SEVERIDADE = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

CAMPOS_CATEGORICOS = ["proto", "source_tool", "app_proto", "event_type"]

CAMPOS_ESCALONADOS = [
    'severity_orig', 'pkts_to_server', 'pkts_to_client',
    'bytes_to_server', 'bytes_to_client', 'duration_s'
]

def ler_entrada(caminho_arquivo):
    """Lê o CSV gerado por unifica_logs.py ou um JSONL compatível."""
    if caminho_arquivo.suffix.lower() == ".csv":
        return pd.read_csv(caminho_arquivo)

    eventos = []
    with caminho_arquivo.open(encoding="utf-8") as arquivo:
        for numero_linha, linha in enumerate(arquivo, 1):
            if not linha.strip():
                continue
            try:
                eventos.append(json.loads(linha))
            except json.JSONDecodeError:
                print(f"Linha JSON inválida encontrada: {numero_linha}")
    return pd.DataFrame(eventos)

def eh_ip_privado(ip):
    try:
        # se for nulo ou float (NaN do pandas), joga pro except
        if pd.isna(ip): 
            return 0
        return 1 if ipaddress.ip_address(str(ip).strip()).is_private else 0
    except:
        return 0 # valor inválido

def extrair_features(caminho_arquivo, caminho_destino):
    df = ler_entrada(caminho_arquivo)

    # --- PASSO 2: Tratamento do Timestamp ---
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    df['is_src_private'] = df['src_ip'].apply(eh_ip_privado)
    df['is_dst_private'] = df['dst_ip'].apply(eh_ip_privado)

    # Passando todas as colunas de uma vez só e salvando de volta no df
    # Removemos a coluna original de timestamp pois ela não vai para o vetor final
    df = df.drop(columns=[
        'timestamp', 'signature', 'signature_id', 'username', 'password', 'category',
        'payload', 'session_id', 'src_log', 'agent_name', 'extra', 'src_ip', 'dst_ip'
    ], errors='ignore')

    # --- PASSO 3: Tratamento de Variáveis Categóricas (One-Hot Encoding) ---
    df_encoded = pd.get_dummies(df, columns=CAMPOS_CATEGORICOS, dtype=int)

    # --- PASSO 4: Normalização de Valores Numéricos (Colocar entre 0 e 1) ---
    scaler = MinMaxScaler()
    df_encoded['severity'] = df_encoded['severity'].fillna('info')

    for campo in CAMPOS_ESCALONADOS:
        df_encoded[campo] = df_encoded[campo].fillna(0)

    df_encoded['severity'] = df_encoded['severity'].map(MAPA_SEVERIDADE)

    # Vamos normalizar a porta de destino e a severidade para a mesma escala
    colunas_normalizadas = ['src_port', 'dst_port', 'hour', 'day_of_week', 'severity']
    df_encoded[colunas_normalizadas] = scaler.fit_transform(df_encoded[colunas_normalizadas])

    # --- PASSO 5: Gerando os Vetores de Características ---
    vetores_caracteristicas = df_encoded.to_numpy()

    print("=== DataFrame Estruturado (Pronto para IA) ===")
    print(df_encoded)

    caminho_destino.parent.mkdir(parents=True, exist_ok=True)
    if caminho_destino.suffix.lower() == ".csv":
        df_encoded.to_csv(caminho_destino, index=False)
    elif caminho_destino.suffix.lower() == ".json":
        df_encoded.to_json(caminho_destino, orient="records", indent=2)
    elif caminho_destino.suffix.lower() == ".jsonl":
        df_encoded.to_json(caminho_destino, orient="records", lines=True)
    else:
        raise ValueError("Extensão de saída deve ser .csv, .jsonl ou .json")


def main():
    parser = argparse.ArgumentParser(description="Extrai características dos logs unificados.")
    parser.add_argument("-i", "--input", required=True, help="arquivo CSV ou JSONL de entrada")
    parser.add_argument("-o", "--output", required=True, help="arquivo .csv, .jsonl ou .json de saída")
    args = parser.parse_args()
    extrair_features(Path(args.input), Path(args.output))


if __name__ == "__main__":
    main()
