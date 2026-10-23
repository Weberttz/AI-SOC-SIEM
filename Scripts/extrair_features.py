"""O script Python lerá o JSON unificado e irá aplicar técnicas de tratamento de dados dependendo do tipo de cada campo:
1. Variáveis Numéricas (Portas, Tamanho do Pacote): Mantêm-se numéricas, mas geralmente aplicamos uma normalização (colocar os valores entre 0 e 1) para que uma porta alta (ex: 54321) não distorça o peso do modelo frente a uma porta baixa (ex: 80).
2. Variáveis Categóricas/Texto (Protocolo, Tipo de Alerta): Modelos não leem "TCP" ou "UDP". Usamos técnicas como One-Hot Encoding (criar colunas binárias de 0 e 1 para cada opção) ou Label Encoding (atribuir um número para cada categoria).
3. Timestamps (Data e Hora): O modelo não entende "2026-10-20T14:00:00Z". Extraímos características numéricas dele, como: Hora do dia (0 a 23), Dia da semana (0 a 6) ou se é Fim de semana (0 ou 1).
4. Endereços IP: Não devem ser convertidos diretamente em número decimal puro. Geralmente, extraímos características deles (ex: O IP é interno ou externo?, Está em uma lista de IPs bloqueados? ou aplicamos técnicas de contagem de frequência)."
"""

import pandas as pd
import numpy as np
import json 
import argparse
import ipaddress
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder
from pathlib import Path

MAPA_SEVERIDADE = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4
}

CAMPOS_CATEGORICOS = ["proto", "source_tool", "app_proto", "event_type"]

CAMPOS_ESCALONADOS = [
    "pkts_to_server", "pkts_to_client",
    "bytes_to_server", "bytes_to_client", "duration_s",
]

CAMPOS_AUSENCIA = [
    f"{campo}_missing"
    for campo in CAMPOS_ESCALONADOS
]

CAMPOS_NUMERICOS = [
    "severity", "src_port", "dst_port", 
    *CAMPOS_ESCALONADOS, *CAMPOS_AUSENCIA,
    "hour", "day_of_week", "is_weekend", "is_src_private",
    "is_dst_private", "src_ip_blocked",
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
        if pd.isna(ip):
            return 0
        return 1 if ipaddress.ip_address(str(ip).strip()).is_private else 0
    except ValueError:
        return 0


def preparar_dados(df):
    """Converte o evento unificado em colunas tipadas para o pré-processador."""
    df = df.copy()
    for campo in ["timestamp", "src_ip", "dst_ip", *CAMPOS_CATEGORICOS,
                  "severity", "src_port", "dst_port", "pkts_to_server",
                  "pkts_to_client", "bytes_to_server", "bytes_to_client",
                  "duration_s"]:
        if campo not in df:
            df[campo] = pd.NA

    timestamp = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["hour"] = timestamp.dt.hour
    df["day_of_week"] = timestamp.dt.day_of_week
    df["is_weekend"] = timestamp.dt.day_of_week.ge(5).fillna(False).astype(int)
    df["is_src_private"] = df["src_ip"].apply(eh_ip_privado)
    df["is_dst_private"] = df["dst_ip"].apply(eh_ip_privado)
    ips_simulados_bloqueados = {"10.93.46.23", "192.168.1.50"}
    df["src_ip_blocked"] = df["src_ip"].isin(ips_simulados_bloqueados).astype(int)

    df["severity"] = (
        df["severity"].astype("string").str.lower().map(MAPA_SEVERIDADE)
    )
    for campo in CAMPOS_CATEGORICOS:
        df[campo] = df[campo].fillna("(ausente)").astype(str)
    # 1. Converte os campos numéricos originais
    for campo in CAMPOS_NUMERICOS:
        if campo not in CAMPOS_AUSENCIA:
            df[campo] = pd.to_numeric(
                df[campo],
                errors="coerce"
            )

    # 2. Trata os campos que serão escalonados
    for campo in CAMPOS_ESCALONADOS:
        valores = df[campo].replace(
            [np.inf, -np.inf], np.nan
        )

        # Registra se o valor estava ausente
        df[f"{campo}_missing"] = valores.isna().astype(int)

        # Substitui valores ausentes por zero
        df[campo] = np.log1p(valores.fillna(0).clip(lower=0))

    # 3. Trata os demais campos numéricos
    for campo in CAMPOS_NUMERICOS:
        df[campo] = (
            df[campo]
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0)
        )

    for campo in ("src_port", "dst_port"):
        valores = df[campo]

        valido = (
            valores.between(0, 65535)
            & (valores % 1 == 0)
        )

        df[campo] = valores.where(valido, 0)

    df["severity"] /= 4
    df["src_port"] /= 65535
    df["dst_port"] /= 65535
    df["hour"] /= 23
    df["day_of_week"] /= 6

    return df[CAMPOS_CATEGORICOS + CAMPOS_NUMERICOS]


def criar_preprocessador():
    return ColumnTransformer(
        transformers=[
            (
                "categoricas",
                OneHotEncoder(handle_unknown="ignore", dtype=int),
                CAMPOS_CATEGORICOS,
            ),
            ("escalonadas", MinMaxScaler(), CAMPOS_ESCALONADOS),
            (
                "numericas_fixas",
                "passthrough",
                [campo for campo in CAMPOS_NUMERICOS if campo not in CAMPOS_ESCALONADOS],
            ),
        ],
        verbose_feature_names_out=False,
    )


def extrair_features(caminho_arquivo, caminho_destino, caminho_preprocessador,
                     ajustar):
    dados = preparar_dados(ler_entrada(caminho_arquivo))
    if ajustar:
        preprocessador = criar_preprocessador()
        transformados = preprocessador.fit_transform(dados)
        caminho_preprocessador.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(preprocessador, caminho_preprocessador)
    else:
        preprocessador = joblib.load(caminho_preprocessador)
        transformados = preprocessador.transform(dados)

    nomes_colunas = preprocessador.get_feature_names_out()
    df_encoded = pd.DataFrame(
        transformados.toarray() if hasattr(transformados, "toarray") else transformados,
        columns=nomes_colunas,
        index=dados.index,
    )

    caminho_destino.parent.mkdir(parents=True, exist_ok=True)
    if caminho_destino.suffix.lower() == ".csv":
        df_encoded.to_csv(caminho_destino, index=False)
    elif caminho_destino.suffix.lower() == ".json":
        df_encoded.to_json(caminho_destino, orient="records", indent=2)
    elif caminho_destino.suffix.lower() == ".jsonl":
        df_encoded.to_json(caminho_destino, orient="records", lines=True)
    else:
        raise ValueError("Extensão de saída deve ser .csv, .jsonl ou .json")

    print(f"Vetor de características gerado: {caminho_destino}")


def main():
    parser = argparse.ArgumentParser(description="Extrai características dos logs unificados.")
    parser.add_argument("-i", "--input", required=True, help="arquivo CSV ou JSONL de entrada")
    parser.add_argument("-o", "--output", required=True, help="arquivo .csv, .jsonl ou .json de saída")
    modo = parser.add_mutually_exclusive_group(required=True)
    modo.add_argument(
        "--fit-preprocessor",
        type=Path,
        metavar="ARQUIVO",
        help="ajusta o pré-processador com os dados de treino e salva em ARQUIVO",
    )
    modo.add_argument(
        "--preprocessor",
        type=Path,
        metavar="ARQUIVO",
        help="carrega o pré-processador ajustado para transformar os dados",
    )
    args = parser.parse_args()
    ajustar = args.fit_preprocessor is not None
    caminho_preprocessador = args.fit_preprocessor or args.preprocessor
    extrair_features(
        Path(args.input),
        Path(args.output),
        caminho_preprocessador,
        ajustar,
    )


if __name__ == "__main__":
    main()
