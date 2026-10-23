# AI-SOC-SIEM

Projeto para consolidar logs de ferramentas de segurança e preparar os eventos para análise e uso em modelos de IA.

## O que o projeto faz

- Unifica logs de Suricata, Zeek, Wazuh, Cowrie, Dionaea e Heralding em um formato comum.
- Analisa conjuntos de dados unificados, mostrando fontes, tipos de evento e campos.
- Extrai características dos eventos, como horário, dia da semana, categorias e indicadores de IP, e salva os dados preparados.

## Estrutura

- `Scripts/unifica_logs.py`: unifica os logs e gera arquivos CSV, JSONL ou JSON.
- `Scripts/analisa_dataset.py`: resume dados unificados em JSONL.
- `Scripts/extrair_features.py`: transforma dados unificados em características para análise ou IA.
- `Dados/` e `Logs/`: exemplos de dados e logs.
- `Logs_unificados/`: exemplos de logs consolidados.
- `Docs/` e `Planilhas/`: documentação e catálogo de dados.

## Requisitos

Python 3. Para extrair características, instale também `pandas` e `scikit-learn`:

```bash
python -m pip install pandas scikit-learn
```

## Uso

Unifique um ou mais arquivos de log:

```bash
python Scripts/unifica_logs.py \
  --cowrie Logs/cowrie.json \
  --dionaea Logs/dionaea.log \
  -o Logs_unificados/unificado.jsonl
```

Analise um arquivo JSONL unificado:

```bash
python Scripts/analisa_dataset.py -i Logs_unificados/unificado.jsonl
```

Ajuste o pré-processador **somente com os dados de treino** e gere os vetores:

```bash
python Scripts/extrair_features.py \
  -i Dados/treino.jsonl \
  -o Dados/treino_features.csv \
  --fit-preprocessor Dados/preprocessador.joblib
```

Reutilize o mesmo pré-processador para validação, teste ou novos eventos:

```bash
python Scripts/extrair_features.py \
  -i Dados/teste.jsonl \
  -o Dados/teste_features.csv \
  --preprocessor Dados/preprocessador.joblib
```

O pré-processador salva as categorias do One-Hot Encoding e os limites do escalonador aprendidos no treino. Categorias novas são ignoradas sem alterar as colunas geradas. Os arquivos de entrada do extrator podem ser CSV ou JSONL; a saída pode ser CSV, JSONL ou JSON. Consulte `--help` para ver as opções disponíveis.

## Atenção aos dados

Logs podem conter senhas, comandos e outros dados sensíveis. Proteja os arquivos gerados e compartilhe-os somente quando apropriado.
