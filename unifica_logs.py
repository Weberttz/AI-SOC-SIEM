#!/usr/bin/env python3
r"""Normaliza logs de Suricata, Zeek, Wazuh, Cowrie, Dionaea e Heralding.
Um evento por linha, usando os mesmos campos normalizados em inglês.
Uso:
    python unifica_logs.py -o unificado.csv \
        --suricata /var/log/suricata/eve.json \
        --zeek /opt/zeek/logs/current/conn.log \
        --wazuh /var/ossec/logs/alerts/alerts.json \
        --cowrie /home/cowrie/var/log/cowrie/cowrie.json \
        --dionaea /opt/dionaea/var/log/dionaea/dionaea.json \
        --heralding /var/log/heralding/log_auth.csv
Aceita vários arquivos ou padrões glob por opção.
Formato da saída: .csv, .jsonl ou .json. Usa apenas a biblioteca padrão.
"""
import argparse
import csv
import glob
import gzip
import json
import sys
from datetime import datetime, timezone


OPCOES = {"cowrie_full": False, "dionaea_tz": "+00:00"}


# ---------------------------------------------------------------- esquema ----
ESQUEMA = [
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
]


# --- utilitários ---
def obter_campo(dados, caminho, padrao=None):
    """Acesso aninhado: obter_campo(evento, 'alert.severity'). Também aceita chave plana
    com ponto (ex.: Zeek em JSON usa 'id.orig_h' como chave literal)."""
    if not isinstance(dados, dict):
        return padrao
    if caminho in dados:
        return dados[caminho]
    atual = dados
    for parte in caminho.split("."):
        if not isinstance(atual, dict) or parte not in atual:
            return padrao
        atual = atual[parte]
    return atual


def primeiro_preenchido(dados, *caminhos, padrao=None):
    """Primeiro valor não vazio entre vários nomes possíveis."""
    for item in caminhos:
        valor = obter_campo(dados, item)
        if valor not in (None, "", "-", "(empty)"):
            return valor
    return padrao


def para_inteiro(valor):
    try:
        return int(float(valor))
    except (TypeError, ValueError):
        return None

def para_decimal(valor):
    try:
        return float(valor)
    except (TypeError, ValueError):
        return None

def normalizar_data_hora(valor):
    """Converte ISO8601 ou epoch (s, ms ou µs) para ISO8601 UTC."""
    if valor in (None, "", "-"):
        return None
    try:
        numero = float(valor)
        # Descobre a unidade pela magnitude
        while numero > 1e11:      # > ano ~5138 em segundos => está em ms/µs/ns
            numero /= 1000.0
        return datetime.fromtimestamp(numero, tz=timezone.utc).isoformat(timespec="microseconds")
    except (TypeError, ValueError):
        pass
    texto = str(valor).strip().replace("Z", "+00:00")
    # '+0000' -> '+00:00' para compatibilidade com versões antigas do Python
    if len(texto) > 5 and texto[-5] in "+-" and texto[-3] != ":":
        texto = texto[:-2] + ":" + texto[-2:]
    try:
        data_hora = datetime.fromisoformat(texto)
    except ValueError:
        return str(valor)  # mantém original em vez de perder o dado
    if data_hora.tzinfo is None:
        data_hora = data_hora.replace(tzinfo=timezone.utc)
    return data_hora.astimezone(timezone.utc).isoformat(timespec="microseconds")


def normalizar_protocolo(valor):
    """Normaliza o nome do protocolo."""
    return str(valor).lower() if valor not in (None, "") else None


def severidade_suricata(valor):          # 1 = alto ... 3 = baixo (conforme catálogo)
    """Normaliza a severidade do Suricata conforme o catálogo."""
    return {1: "high", 2: "medium", 3: "low"}.get(para_inteiro(valor), None)


def severidade_wazuh(valor):             # rule.level 0-16
    """Descreve a severidade do Wazuh."""
    nivel_regra = para_inteiro(valor)
    if nivel_regra is None:
        return None
    if nivel_regra <= 3:
        return "low"
    if nivel_regra <= 7:
        return "medium"
    if nivel_regra <= 11:
        return "high"
    return "critical"


def novo_registro(ferramenta, caminho_log):
    registro = dict.fromkeys(ESQUEMA)
    registro["source_tool"] = ferramenta
    registro["src_log"] = caminho_log
    return registro


def finalizar_registro(registro, extras):
    """Acrescenta campos específicos da ferramenta ao registro normalizado."""
    registro["extra"] = json.dumps(extras, ensure_ascii=False, default=str) if extras else None
    return registro


def campos_restantes(evento, chaves_superiores_usadas):
    """Campos que não entraram no esquema comum ficam preservados em 'extra'."""
    return {chave: valor for chave, valor in evento.items() if chave not in chaves_superiores_usadas}


def abrir_texto(caminho):
    if caminho.endswith(".gz"):
        return gzip.open(caminho, "rt", encoding="utf-8", errors="replace")
    return open(caminho, "r", encoding="utf-8", errors="replace", newline="")


def iterar_jsonl(caminho):
    """Lê arquivos JSONL."""
    with abrir_texto(caminho) as arquivo:
        for contador, linha in enumerate(arquivo, 1):
            linha = linha.strip()
            if not linha:
                continue
            try:
                yield json.loads(linha)
            except json.JSONDecodeError:
                print(f"[aviso] {caminho}:{contador} linha JSON inválida, ignorada", file=sys.stderr)


# ---- analisadores de logs ----
def analisar_suricata(caminho):
    for evento in iterar_jsonl(caminho):
        registro = novo_registro("suricata", caminho)
        registro["timestamp"] = normalizar_data_hora(evento.get("timestamp"))
        registro["event_type"] = evento.get("event_type")
        registro["src_ip"], registro["src_port"] = evento.get("src_ip"), para_inteiro(evento.get("src_port"))
        registro["dst_ip"], registro["dst_port"] = evento.get("dest_ip"), para_inteiro(evento.get("dest_port"))
        registro["proto"] = normalizar_protocolo(evento.get("proto"))
        registro["app_proto"] = evento.get("app_proto")
        registro["session_id"] = evento.get("flow_id")
        alerta = evento.get("alert") or {}
        if alerta:
            registro["severity_orig"] = alerta.get("severity")
            registro["severity"] = severidade_suricata(alerta.get("severity"))
            registro["signature"] = alerta.get("signature")
            registro["signature_id"] = alerta.get("signature_id")
            registro["category"] = alerta.get("category")
        else:
            registro["severity"] = "info"
        detalhes = evento.get("flow") or {}
        registro["pkts_to_server"] = para_inteiro(detalhes.get("pkts_toserver"))
        registro["pkts_to_client"] = para_inteiro(detalhes.get("pkts_toclient"))
        registro["bytes_to_server"] = para_inteiro(detalhes.get("bytes_toserver"))
        registro["bytes_to_client"] = para_inteiro(detalhes.get("bytes_toclient"))
        registro["duration_s"] = para_decimal(detalhes.get("age"))
        extras = campos_restantes(evento, {"timestamp", "event_type", "src_ip", "src_port", "dest_ip",
                          "dest_port", "proto", "app_proto", "flow_id"})
        # remove o que já foi mapeado dentro de alert/flow
        if alerta:
            extras["alert"] = {chave: valor for chave, valor in alerta.items() if chave not in
                              ("severity", "signature", "signature_id", "category")}
        if detalhes:
            extras["flow"] = {chave: valor for chave, valor in detalhes.items() if chave not in
                             ("pkts_toserver", "pkts_toclient", "bytes_toserver",
                              "bytes_toclient", "age")}
        yield finalizar_registro(registro, extras)


CAMPOS_CONEXAO_ZEEK = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
                    "service", "duration", "orig_bytes", "resp_bytes", "conn_state"]

def iterar_zeek(caminho):
    """Aceita Zeek em JSON (uma linha por evento) ou TSV padrão (#fields)."""
    with abrir_texto(caminho) as arquivo:
        campos, separador, ausente, vazio = None, "\t", "-", "(empty)"
        for linha in arquivo:
            linha = linha.rstrip("\n")
            if not linha:
                continue
            if linha.startswith("#"):
                if linha.startswith("#separator"):
                    texto = linha.split(" ", 1)[1].strip()
                    separador = bytes(texto, "utf-8").decode("unicode_escape") if texto.startswith("\\x") else texto
                elif linha.startswith("#fields"):
                    campos = linha.split(separador)[1:]
                elif linha.startswith("#unset_field"):
                    ausente = linha.split(separador)[1]
                continue
            if linha.startswith("{"):
                try:
                    yield json.loads(linha)
                except json.JSONDecodeError:
                    pass
                continue
            if campos:
                valores = linha.split(separador)
                yield {chave: (None if valor in (ausente, vazio) else valor) for chave, valor in zip(campos, valores)}

def analisar_zeek(caminho):
    for evento in iterar_zeek(caminho):
        registro = novo_registro("zeek", caminho)
        registro["timestamp"] = normalizar_data_hora(evento.get("ts"))
        registro["event_type"] = "conn"
        registro["src_ip"], registro["src_port"] = obter_campo(evento, "id.orig_h"), para_inteiro(obter_campo(evento, "id.orig_p"))
        registro["dst_ip"], registro["dst_port"] = obter_campo(evento, "id.resp_h"), para_inteiro(obter_campo(evento, "id.resp_p"))
        registro["proto"] = normalizar_protocolo(evento.get("proto"))
        registro["app_proto"] = evento.get("service")
        registro["severity"] = "info"
        registro["session_id"] = (evento.get("uid") or "").strip() or None
        registro["pkts_to_server"] = para_inteiro(evento.get("orig_pkts"))
        registro["pkts_to_client"] = para_inteiro(evento.get("resp_pkts"))
        registro["bytes_to_server"] = para_inteiro(evento.get("orig_bytes"))
        registro["bytes_to_client"] = para_inteiro(evento.get("resp_bytes"))
        registro["duration_s"] = para_decimal(evento.get("duration"))
        chaves_usadas = {"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
                "service", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"}
        # Zeek em JSON às vezes aninha 'id': {orig_h...}
        extras = campos_restantes(evento, chaves_usadas | {"id"})
        yield finalizar_registro(registro, extras)


def analisar_wazuh(caminho):
    """alerts.json do Wazuh (uma linha por alerta). O evento original da ferramenta
    monitorada fica em 'data.*' e é preservado em extra['data']."""
    for evento in iterar_jsonl(caminho):
        registro = novo_registro("wazuh", caminho)
        registro["timestamp"] = normalizar_data_hora(evento.get("timestamp"))
        dados_evento = evento.get("data") or {}
        registro["event_type"] = "alert"
        # Campos de rede variam conforme o decoder (suricata, cowrie, sshd...)
        registro["src_ip"] = primeiro_preenchido(dados_evento, "src_ip", "srcip", "id.orig_h")
        registro["src_port"] = para_inteiro(primeiro_preenchido(dados_evento, "src_port", "srcport", "id.orig_p"))
        registro["dst_ip"] = primeiro_preenchido(dados_evento, "dest_ip", "dst_ip", "dstip", "id.resp_h")
        registro["dst_port"] = para_inteiro(primeiro_preenchido(dados_evento, "dest_port", "dst_port", "dstport", "id.resp_p"))
        registro["proto"] = normalizar_protocolo(primeiro_preenchido(dados_evento, "proto", "protocol"))
        registro["app_proto"] = primeiro_preenchido(dados_evento, "app_proto")
        regra = evento.get("rule") or {}
        registro["severity_orig"] = regra.get("level")
        registro["severity"] = severidade_wazuh(regra.get("level"))
        registro["signature"] = regra.get("description")
        registro["signature_id"] = regra.get("id")
        registro["category"] = ",".join(regra["groups"]) if isinstance(regra.get("groups"), list) else None
        registro["session_id"] = primeiro_preenchido(dados_evento, "flow_id", "session")
        registro["username"] = primeiro_preenchido(dados_evento, "dstuser", "srcuser", "username")
        registro["agent_name"] = obter_campo(evento, "agent.name")
        extras = {
            "agent": evento.get("agent"),
            "manager": evento.get("manager"),
            "location": evento.get("location"),
            "decoder": evento.get("decoder"),
            "rule_extra": {chave: regra.get(chave) for chave in
                           ("firedtimes", "mitre", "pci_dss", "gdpr", "hipaa", "nist_800_53")
                           if regra.get(chave) is not None},
            "data": dados_evento or None,
            "full_log": evento.get("full_log"),
        }
        extras = {chave: valor for chave, valor in extras.items() if valor not in (None, {}, [])}
        yield finalizar_registro(registro, extras)


CAMPOS_EXTENSOS_COWRIE = {"hasshAlgorithms", "kexAlgs", "keyAlgs", "encCS", "macCS", "compCS", "langCS"}


def analisar_cowrie(caminho):
    """cowrie.json[.AAAA-MM-DD]: um evento por linha, identificado por 'eventid'.
    Duração vem em 'duration_ms'; comando digitado em 'input'.
    As listas enormes de algoritmos do KEX são descartadas (use --cowrie-full
    para mantê-las); o hassh em si é sempre preservado."""
    for evento in iterar_jsonl(caminho):
        identificador_evento = evento.get("eventid", "")
        registro = novo_registro("cowrie", caminho)
        registro["timestamp"] = normalizar_data_hora(evento.get("timestamp"))
        registro["event_type"] = identificador_evento.replace("cowrie.", "") or None
        registro["src_ip"], registro["src_port"] = evento.get("src_ip"), para_inteiro(evento.get("src_port"))
        registro["dst_ip"], registro["dst_port"] = evento.get("dst_ip"), para_inteiro(evento.get("dst_port"))
        registro["proto"] = "tcp"
        registro["app_proto"] = evento.get("protocol") or "ssh"
        registro["session_id"] = evento.get("session")
        registro["username"], registro["password"] = evento.get("username"), evento.get("password")
        registro["payload"] = evento.get("input") or evento.get("url")
        milissegundos = para_decimal(evento.get("duration_ms"))
        registro["duration_s"] = milissegundos / 1000.0 if milissegundos is not None else para_decimal(evento.get("duration"))
        registro["signature"] = evento.get("message") or None
        if identificador_evento.startswith("cowrie.login"):
            registro["severity"] = "low"
        elif identificador_evento in ("cowrie.command.input", "cowrie.session.file_download",
                     "cowrie.session.file_upload"):
            registro["severity"] = "medium"
        else:
            registro["severity"] = "info"
        ignorar = {"timestamp", "eventid", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                "session", "username", "password", "input", "duration_ms", "duration",
                "message", "uuid"}
        if not OPCOES["cowrie_full"]:
            ignorar |= CAMPOS_EXTENSOS_COWRIE
        yield finalizar_registro(registro, campos_restantes(evento, ignorar))


import re


_D_LINHA = re.compile(r"^\[(\d{2})(\d{2})(\d{4}) (\d{2}:\d{2}:\d{2})\] (\S+) (\S+?)-(\w+): ?(.*)$")
_D_INCIDENTE = re.compile(r"^incident (0x[0-9a-f]+) (dionaea\.\S+)$")
_D_CAMPO = re.compile(r"^(\t+)(.+?): \((\w+)\)(?: (.*))?$")
_D_ACEITA = re.compile(r"^accepted connection from (\S+?):(\d+) to (\S+?):(\d+) \(id=(\d+)\)")
_D_CONECTA = re.compile(r"^connect connection to (\S+?)/:(\d+) from (\S+?):(\d+) \(id=(\d+)\)")
_D_EVENTOS = {   # incident -> (event_type, severidade)
    "dionaea.modules.python.ftp.login": ("ftp_login", "low"),
    "dionaea.modules.python.ftp.command": ("ftp_command", "info"),
    "dionaea.modules.python.smb.dcerpc.bind": ("smb_dcerpc_bind", "low"),
    "dionaea.modules.python.smb.dcerpc.request": ("smb_dcerpc_request", "low"),
    "dionaea.modules.python.sip.command": ("sip_command", "info"),
    "dionaea.modules.python.pptp.connect": ("pptp_connect", "info"),
    "dionaea.download.offer": ("download_offer", "medium"),
    "dionaea.download.complete": ("download_complete", "medium"),
    "dionaea.download.complete.hash": ("download_complete", "medium"),
    "dionaea.upload.request": ("upload_request", "medium"),
}
_D_PROTOCOLOS_APLICACAO = {"ftp": "ftp", "smb": "smb", "sip": "sip", "pptp": "pptp"}


def _data_hora_dionaea(dia, mes, ano, horario):
    """Log em texto: [DDMMYYYY HH:MM:SS], sem fuso. Usa --dionaea-tz (padrão UTC)."""
    return normalizar_data_hora(f"{ano}-{mes}-{dia}T{horario}{OPCOES['dionaea_tz']}")


def analisar_dionaea(caminho):
    """Dionaea. Duas formas aceitas:
      * dionaea.log (texto/debug): reconstrói conexões a partir das linhas
        'log_sqlite ... accepted/connect connection ...' e liga cada incidente
        (login FTP, download, DCERPC...) à conexão pelo ponteiro 'con: (ptr)'.
      * JSON por linha (se a primeira linha começar com '{')."""
    with abrir_texto(caminho) as arquivo:
        cabecalho = arquivo.readline().strip()
    if cabecalho.startswith("{"):
        yield from _analisar_dionaea_json(caminho)
        return


    execucao = 0
    mapa_conexoes = {}          # ponteiro da conexão -> dict(src/dst/id/proto)
    incidente_pendente = None       # incidente em leitura: dict(name, ts, fields, args, con)
    ultimo_encerrado = None   # último incidente já lido (liga ao log_sqlite seguinte)


    def emitir_incidente(incidente):
        especificacao = _D_EVENTOS.get(incidente["name"])
        if not especificacao:
            return None
        conexao = mapa_conexoes.get(incidente["con"], {})
        registro = novo_registro("dionaea", caminho)
        registro["timestamp"] = incidente["ts"]
        registro["event_type"], registro["severity"] = especificacao
        registro["src_ip"], registro["src_port"] = conexao.get("src_ip"), conexao.get("src_port")
        registro["dst_ip"], registro["dst_port"] = conexao.get("dst_ip"), conexao.get("dst_port")
        registro["proto"] = conexao.get("proto")
        registro["session_id"] = conexao.get("sid")
        detalhes = incidente["fields"]
        partes = incidente["name"].split(".")
        registro["app_proto"] = next((_D_PROTOCOLOS_APLICACAO[item] for item in partes if item in _D_PROTOCOLOS_APLICACAO), conexao.get("app_proto"))
        registro["username"], registro["password"] = detalhes.get("username"), detalhes.get("password")
        if "download" in incidente["name"] or "upload" in incidente["name"]:
            registro["payload"] = detalhes.get("url") or detalhes.get("md5hash")
        elif detalhes.get("method"):
            registro["payload"] = detalhes["method"]
        elif detalhes.get("command"):
            registro["payload"] = " ".join([detalhes["command"]] + incidente["args"])
        registro["signature"] = incidente["name"].replace("dionaea.", "")
        extras = {chave: valor for chave, valor in detalhes.items() if chave not in ("username", "password", "con")}
        if incidente["args"]:
            extras["args"] = incidente["args"]
        return finalizar_registro(registro, extras)


    def encerrar_incidente(incidente):
        nonlocal ultimo_encerrado
        ultimo_encerrado = incidente
        return emitir_incidente(incidente)


    with abrir_texto(caminho) as arquivo:
        for linha_original in arquivo:
            linha_original = linha_original.rstrip("\n")
            correspondencia = _D_LINHA.match(linha_original)
            if not correspondencia:
                continue        # tracebacks e continuações de linha
            dia, mes, ano, horario, modulo, origem, nivel, mensagem = correspondencia.groups()
            instante = _data_hora_dionaea(dia, mes, ano, horario)


            # campos de incidente (nível 1 = '\t', níveis maiores = sub-estrutura)
            # incident.c:141/149 = cabeçalho de lista/dict aninhado (só pula);
            # incident.c:160 = campo escalar.
            if "incident.c:141" in origem or "incident.c:149" in origem:
                continue
            if "incident.c:160" in origem:
                correspondencia_campo = _D_CAMPO.match(mensagem)
                if incidente_pendente is not None and correspondencia_campo:
                    tabulacoes, nome_campo, tipo_campo, valor_campo = correspondencia_campo.groups()
                    valor_campo = valor_campo if valor_campo is not None else ""
                    if len(tabulacoes) == 1:
                        if nome_campo == "con":
                            incidente_pendente["con"] = valor_campo
                        elif tipo_campo != "none":
                            incidente_pendente["fields"][nome_campo] = valor_campo
                    elif nome_campo == "(null)":
                        incidente_pendente["args"].append(valor_campo)
                continue


            # qualquer outra linha encerra a leitura de campos do incidente anterior
            if incidente_pendente is not None:
                registro = encerrar_incidente(incidente_pendente)
                incidente_pendente = None
                if registro:
                    yield registro


            correspondencia_incidente = _D_INCIDENTE.match(mensagem)
            if correspondencia_incidente:
                incidente_pendente = {"name": correspondencia_incidente.group(2), "ts": instante, "fields": {}, "args": [], "con": None}
                if correspondencia_incidente.group(2) == "dionaea.connection.free":
                    pass
                continue


            if "START THE IHANDLERS" in mensagem:      # reinício do serviço: ids/ponteiros recomeçam
                execucao += 1
                mapa_conexoes.clear()
                continue


            if modulo == "log_sqlite":
                conexao_aceita, conexao_saida = _D_ACEITA.match(mensagem), _D_CONECTA.match(mensagem)
                if not (conexao_aceita or conexao_saida):
                    continue
                incidente = ultimo_encerrado or {"name": "", "con": None}
                nome_incidente = incidente["name"]
                protocolo = "udp" if ".udp." in nome_incidente else "tcp"
                if conexao_aceita:
                    ip_origem, porta_origem, ip_destino, porta_destino, identificador_conexao = conexao_aceita.groups()      # remoto -> honeypot
                    tipo_evento = "connection_accept"
                else:
                    ip_destino, porta_destino, ip_origem, porta_origem, identificador_conexao = conexao_saida.groups()      # honeypot -> remoto
                    tipo_evento = "connection_outbound"
                informacoes = {"src_ip": ip_origem, "src_port": para_inteiro(porta_origem), "dst_ip": ip_destino,
                        "dst_port": para_inteiro(porta_destino), "proto": protocolo, "sid": f"run{execucao}-{identificador_conexao}",
                        "tls": ".tls." in nome_incidente}
                if incidente.get("con"):
                    mapa_conexoes[incidente["con"]] = informacoes
                registro = novo_registro("dionaea", caminho)
                registro["timestamp"] = instante
                registro["event_type"] = tipo_evento
                registro["src_ip"], registro["src_port"] = ip_origem, informacoes["src_port"]
                registro["dst_ip"], registro["dst_port"] = ip_destino, informacoes["dst_port"]
                registro["proto"] = protocolo
                registro["app_proto"] = "tls" if informacoes["tls"] else None
                registro["session_id"] = informacoes["sid"]
                registro["severity"] = "info"
                yield finalizar_registro(registro, {"incident": nome_incidente.replace("dionaea.", "")} if nome_incidente else None)


    if incidente_pendente is not None:
        registro = encerrar_incidente(incidente_pendente)
        if registro:
            yield registro


def _analisar_dionaea_json(caminho):
    for evento in iterar_jsonl(caminho):
        registro = novo_registro("dionaea", caminho)
        registro["timestamp"] = normalizar_data_hora(primeiro_preenchido(evento, "timestamp", "time", "ts"))
        conexao = evento.get("connection") if isinstance(evento.get("connection"), dict) else {}
        registro["event_type"] = primeiro_preenchido(evento, "event_type", "type") or conexao.get("type") or "connection"
        registro["src_ip"] = primeiro_preenchido(evento, "src_ip", "remote_host", "connection.remote_host")
        registro["src_port"] = para_inteiro(primeiro_preenchido(evento, "src_port", "remote_port", "connection.remote_port"))
        registro["dst_ip"] = primeiro_preenchido(evento, "dst_ip", "local_host", "connection.local_host")
        registro["dst_port"] = para_inteiro(primeiro_preenchido(evento, "dst_port", "local_port", "connection.local_port"))
        registro["proto"] = normalizar_protocolo(primeiro_preenchido(evento, "transport", "connection.transport"))
        registro["app_proto"] = primeiro_preenchido(evento, "protocol", "connection.protocol")
        registro["severity"] = "info"
        yield finalizar_registro(registro, evento)


def analisar_heralding(caminho):
    """Heralding: log_auth.csv (padrão) ou JSON por linha.
    Colunas CSV: timestamp,auth_id,session_id,source_ip,source_port,
                 destination_ip,destination_port,protocol,username,password"""
    formato_json = caminho.endswith((".json", ".jsonl", ".json.gz"))
    if formato_json:
        linhas = iterar_jsonl(caminho)
    else:
        def _ler_csv():
            with abrir_texto(caminho) as arquivo:
                yield from csv.DictReader(arquivo)
        linhas = _ler_csv()
    for evento in linhas:
        registro = novo_registro("heralding", caminho)
        registro["timestamp"] = normalizar_data_hora(evento.get("timestamp"))
        registro["event_type"] = "auth"
        registro["src_ip"] = primeiro_preenchido(evento, "source_ip", "src_ip")
        registro["src_port"] = para_inteiro(primeiro_preenchido(evento, "source_port", "src_port"))
        registro["dst_ip"] = primeiro_preenchido(evento, "destination_ip", "dest_ip", "dst_ip")
        registro["dst_port"] = para_inteiro(primeiro_preenchido(evento, "destination_port", "dest_port", "dst_port"))
        registro["proto"] = "tcp"
        registro["app_proto"] = (evento.get("protocol") or "").lower() or None
        registro["session_id"] = evento.get("session_id")
        registro["username"], registro["password"] = evento.get("username"), evento.get("password")
        registro["severity"] = "low"
        extras = {chave: evento[chave] for chave in ("auth_id", "num_auth_attempts") if chave in evento}
        yield finalizar_registro(registro, extras)


ANALISADORES = {
    "suricata": analisar_suricata, "zeek": analisar_zeek, "wazuh": analisar_wazuh,
    "cowrie": analisar_cowrie, "dionaea": analisar_dionaea, "heralding": analisar_heralding,
}


# --- saída ---
def expandir_caminhos(padroes):
    """Expande padrões de arquivos para coletar os logs de cada ferramenta."""
    arquivos = []
    for item in padroes:
        encontrados = sorted(glob.glob(item))
        if not encontrados:
            print(f"[aviso] nada encontrado para: {item}", file=sys.stderr)
        arquivos.extend(encontrados)
    return arquivos


def coletar_registros(argumentos):
    """Percorre as ferramentas e chama o analisador correspondente."""
    for ferramenta, analisador in ANALISADORES.items():
        for caminho in expandir_caminhos(getattr(argumentos, ferramenta) or []):
            contador = 0
            try:
                for registro in analisador(caminho):
                    contador += 1
                    yield registro
            except Exception as erro:   # um arquivo ruim não derruba o restante
                print(f"[erro] {ferramenta} {caminho}: {erro}", file=sys.stderr)
            print(f"[ok] {ferramenta:<9} {contador:>8} eventos  <- {caminho}", file=sys.stderr)


def gravar_saida(registros, saida):
    extensao = saida.lower().rsplit(".", 1)[-1]
    if extensao == "csv":
        with open(saida, "w", newline="", encoding="utf-8") as arquivo:
            escritor = csv.DictWriter(arquivo, fieldnames=ESQUEMA)
            escritor.writeheader()
            for registro in registros:
                escritor.writerow(registro)
    elif extensao == "jsonl":
        with open(saida, "w", encoding="utf-8") as arquivo:
            for registro in registros:
                arquivo.write(json.dumps(registro, ensure_ascii=False) + "\n")
    elif extensao == "json":
        with open(saida, "w", encoding="utf-8") as arquivo:
            json.dump(list(registros), arquivo, ensure_ascii=False, indent=1)
    else:
        sys.exit("Extensão de saída deve ser .csv, .jsonl ou .json")


def main():
    analisador_argumentos = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    for ferramenta in ANALISADORES:
        analisador_argumentos.add_argument(f"--{ferramenta}", nargs="+", metavar="ARQ", help=f"logs do {ferramenta} (aceita glob)")
    analisador_argumentos.add_argument("-o", "--output", required=True)
    analisador_argumentos.add_argument("--cowrie-full", action="store_true",
                    help="mantém as listas de algoritmos KEX do Cowrie em 'extra'")
    analisador_argumentos.add_argument("--dionaea-tz", default="+00:00", metavar="+HH:MM",
                    help="fuso do dionaea.log em texto (não traz fuso). Padrão +00:00")
    analisador_argumentos.add_argument("--sort", action="store_true",
                    help="ordena por timestamp (carrega tudo em memória)")
    argumentos = analisador_argumentos.parse_args()
    OPCOES["cowrie_full"] = argumentos.cowrie_full
    OPCOES["dionaea_tz"] = argumentos.dionaea_tz
    if not any(getattr(argumentos, ferramenta_atual) for ferramenta_atual in ANALISADORES):
        analisador_argumentos.error("informe ao menos um log")


    registros = coletar_registros(argumentos)
    if argumentos.sort:
        registros = sorted(registros, key=lambda registro: registro["timestamp"] or "")
    gravar_saida(registros, argumentos.output)
    print(f"Gerado: {argumentos.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
