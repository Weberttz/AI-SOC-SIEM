import json
from collections import Counter
from pathlib import Path

raiz_do_projeto = Path(__file__).resolve().parent.parent
arquivo = raiz_do_projeto / "Logs_unificados/unificado.jsonl"

total = 0
fontes = Counter()
tipos = Counter()
campos_presentes = Counter()
campos_ausentes = Counter()
campos_vazios = Counter()
campos = set()
timestamps = []

with open(arquivo, "r", encoding="utf-8") as f:
    for linha in f:
        if not linha.strip():
            continue

        try:
            evento = json.loads(linha)
        except json.JSONDecodeError:
            print("Linha JSON inválida encontrada.")
            continue

        total += 1
        fontes[evento.get("source_tool") or "(sem fonte)"] += 1
        tipos[evento.get("event_type") or "(sem tipo)"] += 1

        campos.update(evento.keys())

        for campo, valor in evento.items():
            if valor is None:
                campos_ausentes[campo] += 1
            elif valor == "" or valor == [] or valor == {}:
                campos_vazios[campo] += 1
            else:
                campos_presentes[campo] += 1

        if evento.get("timestamp"):
            timestamps.append(evento["timestamp"])

print(f"\nTotal de eventos: {total}")

print("\nEventos por fonte:")
for fonte, quantidade in fontes.most_common():
    print(f"  {fonte}: {quantidade}")

print("\nTipos de eventos mais frequentes:")
for tipo, quantidade in tipos.most_common(20):
    print(f"  {tipo}: {quantidade}")

print("\nCampos encontrados:")
for campo in sorted(campos):
    presentes = campos_presentes[campo]
    ausentes = campos_ausentes[campo]
    vazios = campos_vazios[campo]
    print(
        f"  {campo}: preenchidos={presentes}, "
        f"null={ausentes}, vazios={vazios}"
    )

if timestamps:
    print("\nPeríodo coberto pelos timestamps:")
    print(f"  Primeiro: {min(timestamps)}")
    print(f"  Último:   {max(timestamps)}")