# text-sanitizer-br

[![test](https://github.com/uilhamello/text-sanitizer-br/actions/workflows/test.yml/badge.svg)](https://github.com/uilhamello/text-sanitizer-br/actions/workflows/test.yml)

**Mascara dados pessoais e segredos em texto livre, e bloqueia o que não dá para mascarar com
segurança.** Feito para documentos brasileiros (CPF, CNPJ, RG, CEP, placa, telefone) e para o que
costuma vazar em log, ticket e prompt de LLM (tokens, senhas, connection strings). Offline: nada
sai da máquina.

Não é um sanitizador de HTML (contra XSS). É mascaramento de PII.

É a **região Brasil** do [text-sanitizer-core](https://github.com/uilhamello/text-sanitizer-core):
o core traz o motor e as regras que não dependem de país (segredos, e-mail, cartão, IP); este
pacote acrescenta documentos, telefone, placa, endereço e o modelo de nomes em português. Instalar
este pacote já traz o core.

## Instalação

```bash
pip install "text-sanitizer-br @ https://github.com/uilhamello/text-sanitizer-br/archive/refs/tags/v0.3.2.zip"
```

Sem dependências. Para mascarar **nomes de pessoas**, instale o extra `ner` (spaCy + modelo
`pt_core_news_sm` fixado por versão e hash; ~340 MB instalados, quase tudo spaCy e numpy):

```bash
pip install "text-sanitizer-br[ner] @ https://github.com/uilhamello/text-sanitizer-br/archive/refs/tags/v0.3.2.zip"
```

## Uso

```bash
echo "João da Silva, CPF 123.456.789-09, Rua Augusta, 1500" | text-sanitizer-br --ner
# <PERSON>, CPF <CPF>, <ADDRESS>
```

O relatório (máscaras e bloqueios) vai para o stderr. Código de saída: `0` ok, `2` bloqueado
(nesse caso nada é impresso no stdout).

```python
from text_sanitizer_br import Sanitizer, sanitize

clean, report = sanitize("contato fulano@example.com")   # regras padrão, sem nomes
report.ok          # False quando algo foi bloqueado: não use o texto
report.masks       # {"email": 1}

s = Sanitizer(ner=True, extra_masks=[("ticket", r"\bTCK-\d+\b", "<TICKET>")])
clean, report = s.sanitize(texto)
```

## O que faz

| Ação | Alvo |
|---|---|
| **Mascara** | nome de pessoa (com `ner=True`), endereço (logradouro + número), e-mail, CPF, RG, CNPJ, CEP, cartão (Luhn), telefone BR, placa BR, IP, UUID, JWT, `Bearer`, tokens com prefixo conhecido, `senha=`/`token=` (também em JSON e texto corrido), credencial e query string em URL, hex longo, número de 6+ dígitos, `*_id=`, login (`login=`, `usuário:`, `@nome.sobrenome`) |
| **Bloqueia** | chave AWS, chave de service account GCP, PEM, connection string, string de alta entropia, `@` residual, texto acima de `max_chars`, `ner=True` sem o modelo instalado |

Regras próprias entram por `extra_masks` e `extra_blocks`. As padrão não podem ser removidas.
As `extra_masks` rodam logo depois dos segredos e antes das outras regras: `TCK-4521` vira `<TICKET>`, não placa.

**Por que `ner=True` sem modelo bloqueia em vez de seguir:** quem pediu nomes mascarados e recebe
o texto com nomes não tem como perceber. Falhar é mais seguro.

## Comparação medida (03/10/2026)

Mesmos 14 textos fictícios, Microsoft Presidio 2.2 com `pt_core_news_md`:

| | Presidio | text-sanitizer-br |
|---|---|---|
| Nome de pessoa | ✅ | ✅ com `ner=True` |
| Cartão, `Bearer`, CNPJ | vaza | ✅ |
| Métrica (`p95 624 s`) | vira `<LOCATION>` | intacta |
| Tempo por texto | ~25 ms | ~0,06 ms (regex) · ~3 ms (com `ner`) |
| Instalado | ~445 MB | ~0 · ~340 MB (com `ner`) |

## Benchmark de vazamento (25/11/2026)

Dois conjuntos de textos fictícios em [`benchmark/`](benchmark/), rodados com `ner=True`
(spaCy 3.8, `pt_core_news_sm` 3.8.0):

| Conjunto | O que mede | Resultado |
|---|---|---|
| `leak.py` · 139 casos | segredo, documento, e-mail, IP, nome, loja, endereço e ID escritos de formas variadas | **0 vazamentos** |
| `fp.py` · 80 textos | log, SQL, stack trace e métrica sem dado pessoal, que deveriam passar intactos | **30 alterados** |

Quase todos os 30 vêm do modelo de nomes, que marca termos técnicos como pessoa (`Lock wait`,
`SQLSTATE`, chave de Jira). O texto continua legível, mas perde contexto. Os casos foram escritos
por quem escreveu as regras: um conjunto de outra pessoa provavelmente acha vazamentos novos.

```bash
PYTHONPATH=../text-sanitizer-core/src:src python benchmark/leak.py
PYTHONPATH=../text-sanitizer-core/src:src python benchmark/fp.py
```

## Limites

- Nome em minúsculas ou fora de frase pode escapar: o modelo depende de contexto.
- Endereço exige logradouro **e** número. Cidade e bairro soltos passam.
- Número de 6+ dígitos sem separador vira `<N>`. Escreva métricas como `51.000.000` ou `51M`.
- Regex e NER não substituem minimização: não leve o dado pessoal se não precisar dele.
- Nome de tabela, serviço, projeto de nuvem ou termo interno não é PII e passa. Para esconder, use
  `extra_masks` com a sua lista: `Sanitizer(extra_masks=[("interno", r"\b(?:meu-projeto|tb_clientes)\b", "<INTERNO>")])`.
- Nome solto com artigo ("o Fulano") só é pego antes de verbo de pessoa ("reclamou", "ligou"...)
  ou depois de "falei com"; em outra posição depende do modelo.
- Nome de loja é pego depois de "loja", "concessionária", "revenda", "empresa", "filial" ou "garagem"
  (com ou sem dois-pontos), antes de Ltda/S.A./EIRELI/EPP/ME, em "X Comércio de Y" e quando duas ou
  mais palavras com maiúscula terminam em Veículos, Automóveis, Motors, Multimarcas, Seminovos, Autos,
  Imóveis, Distribuidora, Transportes ou Representações. Nome de loja sem nenhuma dessas pistas passa.
- Nome de pessoa também é pego depois de papel com dois-pontos ("Atendente: X"), em campo JSON de
  nome (`"nome"`, `"full_name"`...), em despedida no fim da linha ("Att, X") e antes de verbo de pessoa
  ("cliente X reclamou"). Efeito colateral aceito: `nome: Cloud Run` também vira `<PERSON>`.
- Endereço depois de "endereço:" ou "logradouro:" é mascarado até o fim da linha, mesmo sem número.
- Saudação ("Prezado X,", "Oi X,") e nome no começo da linha antes de verbo de pessoa ("X ligou ontem")
  também são pegos. Efeito colateral aceito: "Oi Redis," e "Redis ligou o alerta" viram `<PERSON>`.
- Número curto vira `<ID>` só depois de palavra de entidade ("usuário 4521", "pedido nº 12",
  "/usuarios/4521/") ou de chave de ID (`userId=`, `user_id`, `uid=`, `cod_cliente=`).
- Login vira `<USER>` depois de "login", "usuário", "username" ou "author", em `@nome.sobrenome` e em
  "by nome.sobrenome". Login solto, sem essas pistas, passa. Decorators de código (`@app.route`,
  `@login_required`) ficam intactos.

## Como região do core

O pacote registra `REGION` no grupo de entry points `text_sanitizers` com o nome `br`. Para
juntar várias regiões numa passada só, use o core:

```python
from text_sanitizer_core import build

s = build(["br"], ner=True)   # futuramente: build(["br", "eu"])
clean, report = s.sanitize(texto)
```

## Quem usa

[jev-sanitizer](https://github.com/uilhamello/jev-sanitizer): cliente do Jev (TypeSafe) que passa
todo pedido por aqui antes de enviar.

## Desenvolvimento

```bash
git clone https://github.com/uilhamello/text-sanitizer-br.git && cd text-sanitizer-br
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Os testes de nomes só rodam com o extra instalado (`pip install -e ".[ner]"`). No CI, um job
dedicado falha se eles forem pulados.

Licença MIT.
