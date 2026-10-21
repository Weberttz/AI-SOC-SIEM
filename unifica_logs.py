#!/usr/bin/env python3
"""
unifica_logs.py - Normaliza logs de Suricata, Zeek, Wazuh, Cowrie, Dionaea e
Heralding em um esquema comum (um evento por linha).

Uso:
    python unifica_logs.py -o unificado.csv \
        --suricata /var/log/suricata/eve.json \
        --zeek /opt/zeek/logs/current/conn.log \
        --wazuh /var/ossec/logs/alerts/alerts.json \
        --cowrie /home/cowrie/var/log/cowrie/cowrie.json \
        --dionaea /opt/dionaea/var/log/dionaea/dionaea.json \
        --heralding /var/log/heralding/log_auth.csv

Cada opção aceita vários arquivos/globs. Formato de saída pela extensão do -o:
.csv, .jsonl ou .json (lista).
Só usa a biblioteca padrão.
"""
import argparse
import csv
import glob
import gzip
import json
import sys
from datetime import datetime, timezone

OPTIONS = {"cowrie_full": False, "dionaea_tz": "+00:00"}

# ---------------------------------------------------------------- esquema ----
SCHEMA = [
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


# --------------------------------------------------------------- utilitários --
def get(d, path, default=None):
    """Acesso aninhado: get(ev, 'alert.severity'). Também aceita chave plana
    com ponto (ex.: Zeek em JSON usa 'id.orig_h' como chave literal)."""
    if not isinstance(d, dict):
        return default
    if path in d:
        return d[path]
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def first(d, *paths, default=None):
    """Primeiro valor não vazio entre vários nomes possíveis."""
    for p in paths:
        v = get(d, p)
        if v not in (None, "", "-", "(empty)"):
            return v
    return default


def to_int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def norm_ts(v):
    """Converte ISO8601 ou epoch (s, ms ou µs) para ISO8601 UTC."""
    if v in (None, "", "-"):
        return None
    try:
        x = float(v)
        # Descobre a unidade pela magnitude
        while x > 1e11:      # > ano ~5138 em segundos => está em ms/µs/ns
            x /= 1000.0
        return datetime.fromtimestamp(x, tz=timezone.utc).isoformat(timespec="microseconds")
    except (TypeError, ValueError):
        pass
    s = str(v).strip().replace("Z", "+00:00")
    # '+0000' -> '+00:00' para compatibilidade com versões antigas do Python
    if len(s) > 5 and s[-5] in "+-" and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return str(v)  # mantém original em vez de perder o dado
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def norm_proto(v):
    """Normaliza nome de protocolo"""
    return str(v).lower() if v not in (None, "") else None


def sev_suricata(v):          # 1 = alto ... 3 = baixo (conforme catálogo)
    """Descreve severidade baseado no catálogo dos dados (Planilha)"""
    return {1: "high", 2: "medium", 3: "low"}.get(to_int(v), None)


def sev_wazuh(v):             # rule.level 0-16
    """"Descreve severidade do Wazuh"""
    n = to_int(v)
    if n is None:
        return None
    if n <= 3:
        return "low"
    if n <= 7:
        return "medium"
    if n <= 11:
        return "high"
    return "critical"


def new_record(tool, src_log):
    r = dict.fromkeys(SCHEMA)
    r["source_tool"] = tool
    r["src_log"] = src_log
    return r


def finish(r, extra):
    """Se quiser adicionar dados extras, do dionaea por exemplo"""
    r["extra"] = json.dumps(extra, ensure_ascii=False, default=str) if extra else None
    return r


def rest(ev, used_top_keys):
    """Campos que não entraram no esquema comum ficam preservados em 'extra'."""
    return {k: v for k, v in ev.items() if k not in used_top_keys}


def open_text(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace", newline="")


def iter_jsonl(path):
    """"Ler em jsonl"""
    with open_text(path) as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"[aviso] {path}:{n} linha JSON inválida, ignorada", file=sys.stderr)


# ---- parsers ----
def parse_suricata(path):
    for ev in iter_jsonl(path):
        r = new_record("suricata", path)
        r["timestamp"] = norm_ts(ev.get("timestamp"))
        r["event_type"] = ev.get("event_type")
        r["src_ip"], r["src_port"] = ev.get("src_ip"), to_int(ev.get("src_port"))
        r["dst_ip"], r["dst_port"] = ev.get("dest_ip"), to_int(ev.get("dest_port"))
        r["proto"] = norm_proto(ev.get("proto"))
        r["app_proto"] = ev.get("app_proto")
        r["session_id"] = ev.get("flow_id")
        a = ev.get("alert") or {}
        if a:
            r["severity_orig"] = a.get("severity")
            r["severity"] = sev_suricata(a.get("severity"))
            r["signature"] = a.get("signature")
            r["signature_id"] = a.get("signature_id")
            r["category"] = a.get("category")
        else:
            r["severity"] = "info"
        f = ev.get("flow") or {}
        r["pkts_to_server"] = to_int(f.get("pkts_toserver"))
        r["pkts_to_client"] = to_int(f.get("pkts_toclient"))
        r["bytes_to_server"] = to_int(f.get("bytes_toserver"))
        r["bytes_to_client"] = to_int(f.get("bytes_toclient"))
        r["duration_s"] = to_float(f.get("age"))
        extra = rest(ev, {"timestamp", "event_type", "src_ip", "src_port", "dest_ip",
                          "dest_port", "proto", "app_proto", "flow_id"})
        # remove o que já foi mapeado dentro de alert/flow
        if a:
            extra["alert"] = {k: v for k, v in a.items() if k not in
                              ("severity", "signature", "signature_id", "category")}
        if f:
            extra["flow"] = {k: v for k, v in f.items() if k not in
                             ("pkts_toserver", "pkts_toclient", "bytes_toserver",
                              "bytes_toclient", "age")}
        yield finish(r, extra)


ZEEK_CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
                    "service", "duration", "orig_bytes", "resp_bytes", "conn_state"]


def iter_zeek(path):
    """Aceita Zeek em JSON (uma linha por evento) ou TSV padrão (#fields)."""
    with open_text(path) as fh:
        fields, sep, unset, empty = None, "\t", "-", "(empty)"
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("#separator"):
                    s = line.split(" ", 1)[1].strip()
                    sep = bytes(s, "utf-8").decode("unicode_escape") if s.startswith("\\x") else s
                elif line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                elif line.startswith("#unset_field"):
                    unset = line.split(sep)[1]
                continue
            if line.startswith("{"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass
                continue
            if fields:
                vals = line.split(sep)
                yield {k: (None if v in (unset, empty) else v) for k, v in zip(fields, vals)}


def parse_zeek(path):
    for ev in iter_zeek(path):
        r = new_record("zeek", path)
        r["timestamp"] = norm_ts(ev.get("ts"))
        r["event_type"] = "conn"
        r["src_ip"], r["src_port"] = get(ev, "id.orig_h"), to_int(get(ev, "id.orig_p"))
        r["dst_ip"], r["dst_port"] = get(ev, "id.resp_h"), to_int(get(ev, "id.resp_p"))
        r["proto"] = norm_proto(ev.get("proto"))
        r["app_proto"] = ev.get("service")
        r["severity"] = "info"
        r["session_id"] = (ev.get("uid") or "").strip() or None
        r["pkts_to_server"] = to_int(ev.get("orig_pkts"))
        r["pkts_to_client"] = to_int(ev.get("resp_pkts"))
        r["bytes_to_server"] = to_int(ev.get("orig_bytes"))
        r["bytes_to_client"] = to_int(ev.get("resp_bytes"))
        r["duration_s"] = to_float(ev.get("duration"))
        used = {"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
                "service", "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"}
        # Zeek em JSON às vezes aninha 'id': {orig_h...}
        extra = rest(ev, used | {"id"})
        yield finish(r, extra)


def parse_wazuh(path):
    """alerts.json do Wazuh (uma linha por alerta). O evento original da ferramenta
    monitorada fica em 'data.*' e é preservado em extra['data']."""
    for ev in iter_jsonl(path):
        r = new_record("wazuh", path)
        r["timestamp"] = norm_ts(ev.get("timestamp"))
        data = ev.get("data") or {}
        r["event_type"] = "alert"
        # Campos de rede variam conforme o decoder (suricata, cowrie, sshd...)
        r["src_ip"] = first(data, "src_ip", "srcip", "id.orig_h")
        r["src_port"] = to_int(first(data, "src_port", "srcport", "id.orig_p"))
        r["dst_ip"] = first(data, "dest_ip", "dst_ip", "dstip", "id.resp_h")
        r["dst_port"] = to_int(first(data, "dest_port", "dst_port", "dstport", "id.resp_p"))
        r["proto"] = norm_proto(first(data, "proto", "protocol"))
        r["app_proto"] = first(data, "app_proto")
        rule = ev.get("rule") or {}
        r["severity_orig"] = rule.get("level")
        r["severity"] = sev_wazuh(rule.get("level"))
        r["signature"] = rule.get("description")
        r["signature_id"] = rule.get("id")
        r["category"] = ",".join(rule["groups"]) if isinstance(rule.get("groups"), list) else None
        r["session_id"] = first(data, "flow_id", "session")
        r["username"] = first(data, "dstuser", "srcuser", "username")
        r["agent_name"] = get(ev, "agent.name")
        extra = {
            "agent": ev.get("agent"),
            "manager": ev.get("manager"),
            "location": ev.get("location"),
            "decoder": ev.get("decoder"),
            "rule_extra": {k: rule.get(k) for k in
                           ("firedtimes", "mitre", "pci_dss", "gdpr", "hipaa", "nist_800_53")
                           if rule.get(k) is not None},
            "data": data or None,
            "full_log": ev.get("full_log"),
        }
        extra = {k: v for k, v in extra.items() if v not in (None, {}, [])}
        yield finish(r, extra)


COWRIE_BIG = {"hasshAlgorithms", "kexAlgs", "keyAlgs", "encCS", "macCS", "compCS", "langCS"}


def parse_cowrie(path):
    """cowrie.json[.AAAA-MM-DD]: um evento por linha, identificado por 'eventid'.
    Duração vem em 'duration_ms'; comando digitado em 'input'.
    As listas enormes de algoritmos do KEX são descartadas (use --cowrie-full
    para mantê-las); o hassh em si é sempre preservado."""
    for ev in iter_jsonl(path):
        eid = ev.get("eventid", "")
        r = new_record("cowrie", path)
        r["timestamp"] = norm_ts(ev.get("timestamp"))
        r["event_type"] = eid.replace("cowrie.", "") or None
        r["src_ip"], r["src_port"] = ev.get("src_ip"), to_int(ev.get("src_port"))
        r["dst_ip"], r["dst_port"] = ev.get("dst_ip"), to_int(ev.get("dst_port"))
        r["proto"] = "tcp"
        r["app_proto"] = ev.get("protocol") or "ssh"
        r["session_id"] = ev.get("session")
        r["username"], r["password"] = ev.get("username"), ev.get("password")
        r["payload"] = ev.get("input") or ev.get("url")
        ms = to_float(ev.get("duration_ms"))
        r["duration_s"] = ms / 1000.0 if ms is not None else to_float(ev.get("duration"))
        r["signature"] = ev.get("message") or None
        if eid.startswith("cowrie.login"):
            r["severity"] = "low"
        elif eid in ("cowrie.command.input", "cowrie.session.file_download",
                     "cowrie.session.file_upload"):
            r["severity"] = "medium"
        else:
            r["severity"] = "info"
        skip = {"timestamp", "eventid", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                "session", "username", "password", "input", "duration_ms", "duration",
                "message", "uuid"}
        if not OPTIONS["cowrie_full"]:
            skip |= COWRIE_BIG
        yield finish(r, rest(ev, skip))


import re

_D_LINE = re.compile(r"^\[(\d{2})(\d{2})(\d{4}) (\d{2}:\d{2}:\d{2})\] (\S+) (\S+?)-(\w+): ?(.*)$")
_D_INCIDENT = re.compile(r"^incident (0x[0-9a-f]+) (dionaea\.\S+)$")
_D_FIELD = re.compile(r"^(\t+)(.+?): \((\w+)\)(?: (.*))?$")
_D_ACCEPT = re.compile(r"^accepted connection from (\S+?):(\d+) to (\S+?):(\d+) \(id=(\d+)\)")
_D_CONNECT = re.compile(r"^connect connection to (\S+?)/:(\d+) from (\S+?):(\d+) \(id=(\d+)\)")
_D_EVENTS = {   # incident -> (event_type, severidade)
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
_D_APP = {"ftp": "ftp", "smb": "smb", "sip": "sip", "pptp": "pptp"}


def _dio_ts(d, mo, y, hms):
    """Log em texto: [DDMMYYYY HH:MM:SS], sem fuso. Usa --dionaea-tz (padrão UTC)."""
    return norm_ts(f"{y}-{mo}-{d}T{hms}{OPTIONS['dionaea_tz']}")


def parse_dionaea(path):
    """Dionaea. Duas formas aceitas:
      * dionaea.log (texto/debug): reconstrói conexões a partir das linhas
        'log_sqlite ... accepted/connect connection ...' e liga cada incidente
        (login FTP, download, DCERPC...) à conexão pelo ponteiro 'con: (ptr)'.
      * JSON por linha (se a primeira linha começar com '{')."""
    with open_text(path) as fh:
        head = fh.readline().strip()
    if head.startswith("{"):
        yield from _parse_dionaea_json(path)
        return

    run = 0
    conmap = {}          # ponteiro da conexão -> dict(src/dst/id/proto)
    pending = None       # incidente em leitura: dict(name, ts, fields, args, con)
    last_closed = None   # último incidente já lido (liga ao log_sqlite seguinte)

    def emit_incident(inc):
        spec = _D_EVENTS.get(inc["name"])
        if not spec:
            return None
        con = conmap.get(inc["con"], {})
        r = new_record("dionaea", path)
        r["timestamp"] = inc["ts"]
        r["event_type"], r["severity"] = spec
        r["src_ip"], r["src_port"] = con.get("src_ip"), con.get("src_port")
        r["dst_ip"], r["dst_port"] = con.get("dst_ip"), con.get("dst_port")
        r["proto"] = con.get("proto")
        r["session_id"] = con.get("sid")
        f = inc["fields"]
        parts = inc["name"].split(".")
        r["app_proto"] = next((_D_APP[p] for p in parts if p in _D_APP), con.get("app_proto"))
        r["username"], r["password"] = f.get("username"), f.get("password")
        if "download" in inc["name"] or "upload" in inc["name"]:
            r["payload"] = f.get("url") or f.get("md5hash")
        elif f.get("method"):
            r["payload"] = f["method"]
        elif f.get("command"):
            r["payload"] = " ".join([f["command"]] + inc["args"])
        r["signature"] = inc["name"].replace("dionaea.", "")
        extra = {k: v for k, v in f.items() if k not in ("username", "password", "con")}
        if inc["args"]:
            extra["args"] = inc["args"]
        return finish(r, extra)

    def close(inc):
        nonlocal last_closed
        last_closed = inc
        return emit_incident(inc)

    with open_text(path) as fh:
        for raw in fh:
            raw = raw.rstrip("\n")
            m = _D_LINE.match(raw)
            if not m:
                continue        # tracebacks e continuações de linha
            d, mo, y, hms, _mod, _src, _lvl, msg = m.groups()
            ts = _dio_ts(d, mo, y, hms)

            # campos de incidente (nível 1 = '\t', níveis maiores = sub-estrutura)
            # incident.c:141/149 = cabeçalho de lista/dict aninhado (só pula);
            # incident.c:160 = campo escalar.
            if "incident.c:141" in _src or "incident.c:149" in _src:
                continue
            if "incident.c:160" in _src:
                fm = _D_FIELD.match(msg)
                if pending is not None and fm:
                    tabs, key, typ, val = fm.groups()
                    val = val if val is not None else ""
                    if len(tabs) == 1:
                        if key == "con":
                            pending["con"] = val
                        elif typ != "none":
                            pending["fields"][key] = val
                    elif key == "(null)":
                        pending["args"].append(val)
                continue

            # qualquer outra linha encerra a leitura de campos do incidente anterior
            if pending is not None:
                rec = close(pending)
                pending = None
                if rec:
                    yield rec

            im = _D_INCIDENT.match(msg)
            if im:
                pending = {"name": im.group(2), "ts": ts, "fields": {}, "args": [], "con": None}
                if im.group(2) == "dionaea.connection.free":
                    pass
                continue

            if "START THE IHANDLERS" in msg:      # reinício do serviço: ids/ponteiros recomeçam
                run += 1
                conmap.clear()
                continue

            if _mod == "log_sqlite":
                am, cm = _D_ACCEPT.match(msg), _D_CONNECT.match(msg)
                if not (am or cm):
                    continue
                inc = last_closed or {"name": "", "con": None}
                nm = inc["name"]
                proto = "udp" if ".udp." in nm else "tcp"
                if am:
                    sip_, sp, dip, dp, cid = am.groups()      # remoto -> honeypot
                    ev_type = "connection_accept"
                else:
                    dip, dp, sip_, sp, cid = cm.groups()      # honeypot -> remoto
                    ev_type = "connection_outbound"
                info = {"src_ip": sip_, "src_port": to_int(sp), "dst_ip": dip,
                        "dst_port": to_int(dp), "proto": proto, "sid": f"run{run}-{cid}",
                        "tls": ".tls." in nm}
                if inc.get("con"):
                    conmap[inc["con"]] = info
                r = new_record("dionaea", path)
                r["timestamp"] = ts
                r["event_type"] = ev_type
                r["src_ip"], r["src_port"] = sip_, info["src_port"]
                r["dst_ip"], r["dst_port"] = dip, info["dst_port"]
                r["proto"] = proto
                r["app_proto"] = "tls" if info["tls"] else None
                r["session_id"] = info["sid"]
                r["severity"] = "info"
                yield finish(r, {"incident": nm.replace("dionaea.", "")} if nm else None)

    if pending is not None:
        rec = close(pending)
        if rec:
            yield rec


def _parse_dionaea_json(path):
    for ev in iter_jsonl(path):
        r = new_record("dionaea", path)
        r["timestamp"] = norm_ts(first(ev, "timestamp", "time", "ts"))
        conn = ev.get("connection") if isinstance(ev.get("connection"), dict) else {}
        r["event_type"] = first(ev, "event_type", "type") or conn.get("type") or "connection"
        r["src_ip"] = first(ev, "src_ip", "remote_host", "connection.remote_host")
        r["src_port"] = to_int(first(ev, "src_port", "remote_port", "connection.remote_port"))
        r["dst_ip"] = first(ev, "dst_ip", "local_host", "connection.local_host")
        r["dst_port"] = to_int(first(ev, "dst_port", "local_port", "connection.local_port"))
        r["proto"] = norm_proto(first(ev, "transport", "connection.transport"))
        r["app_proto"] = first(ev, "protocol", "connection.protocol")
        r["severity"] = "info"
        yield finish(r, ev)


def parse_heralding(path):
    """Heralding: log_auth.csv (padrão) ou JSON por linha.
    Colunas CSV: timestamp,auth_id,session_id,source_ip,source_port,
                 destination_ip,destination_port,protocol,username,password"""
    is_json = path.endswith((".json", ".jsonl", ".json.gz"))
    if is_json:
        rows = iter_jsonl(path)
    else:
        def _csv():
            with open_text(path) as fh:
                yield from csv.DictReader(fh)
        rows = _csv()
    for ev in rows:
        r = new_record("heralding", path)
        r["timestamp"] = norm_ts(ev.get("timestamp"))
        r["event_type"] = "auth"
        r["src_ip"] = first(ev, "source_ip", "src_ip")
        r["src_port"] = to_int(first(ev, "source_port", "src_port"))
        r["dst_ip"] = first(ev, "destination_ip", "dest_ip", "dst_ip")
        r["dst_port"] = to_int(first(ev, "destination_port", "dest_port", "dst_port"))
        r["proto"] = "tcp"
        r["app_proto"] = (ev.get("protocol") or "").lower() or None
        r["session_id"] = ev.get("session_id")
        r["username"], r["password"] = ev.get("username"), ev.get("password")
        r["severity"] = "low"
        extra = {k: ev[k] for k in ("auth_id", "num_auth_attempts") if k in ev}
        yield finish(r, extra)


PARSERS = {
    "suricata": parse_suricata, "zeek": parse_zeek, "wazuh": parse_wazuh,
    "cowrie": parse_cowrie, "dionaea": parse_dionaea, "heralding": parse_heralding,
}


# --- saída ---
def expand(patterns):
    """Ler todos os logs da ferramenta indicada. Aceita arquivos, globs (logs/*.json) e diretórios"""
    files = []
    for p in patterns:
        hits = sorted(glob.glob(p))
        if not hits:
            print(f"[aviso] nada encontrado para: {p}", file=sys.stderr)
        files.extend(hits)
    return files


def collect(args):
    """Percorre cada ferramenta e chama o parser certo"""
    for tool, parser in PARSERS.items():
        for path in expand(getattr(args, tool) or []):
            n = 0
            try:
                for rec in parser(path):
                    n += 1
                    yield rec
            except Exception as exc:   # um arquivo ruim não derruba o restante
                print(f"[erro] {tool} {path}: {exc}", file=sys.stderr)
            print(f"[ok] {tool:<9} {n:>8} eventos  <- {path}", file=sys.stderr)


def write_output(records, out):
    ext = out.lower().rsplit(".", 1)[-1]
    if ext == "csv":
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=SCHEMA)
            w.writeheader()
            for r in records:
                w.writerow(r)
    elif ext == "jsonl":
        with open(out, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    elif ext == "json":
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(list(records), fh, ensure_ascii=False, indent=1)
    else:
        sys.exit("Extensão de saída deve ser .csv, .jsonl ou .json")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    for tool in PARSERS:
        ap.add_argument(f"--{tool}", nargs="+", metavar="ARQ", help=f"logs do {tool} (aceita glob)")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--cowrie-full", action="store_true",
                    help="mantém as listas de algoritmos KEX do Cowrie em 'extra'")
    ap.add_argument("--dionaea-tz", default="+00:00", metavar="+HH:MM",
                    help="fuso do dionaea.log em texto (não traz fuso). Padrão +00:00")
    ap.add_argument("--sort", action="store_true",
                    help="ordena por timestamp (carrega tudo em memória)")
    args = ap.parse_args()
    OPTIONS["cowrie_full"] = args.cowrie_full
    OPTIONS["dionaea_tz"] = args.dionaea_tz
    if not any(getattr(args, t) for t in PARSERS):
        ap.error("informe ao menos um log")

    records = collect(args)
    if args.sort:
        records = sorted(records, key=lambda r: r["timestamp"] or "")
    write_output(records, args.output)
    print(f"Gerado: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()