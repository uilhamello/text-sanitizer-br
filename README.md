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
pip install "text-sanitizer-br @ https://github.com/uilhamello/text-sanitizer-br/archive/refs/tags/v0.2.0.zip"
```

Sem dependências. Para mascarar **nomes de pessoas**, instale o extra `ner` (spaCy + modelo
`pt_core_news_sm` fixado por versão e hash; ~340 MB instalados, quase tudo spaCy e numpy):

```bash
pip install "text-sanitizer-br[ner] @ https://github.com/uilhamello/text-sanitizer-br/archive/refs/tags/v0.2.0.zip"
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
| **Mascara** | nome de pessoa (com `ner=True`), endereço (logradouro + número), e-mail, CPF, RG, CNPJ, CEP, cartão (Luhn), telefone BR, placa BR, IP, UUID, JWT, `Bearer`, tokens com prefixo conhecido, `senha=`/`token=` (também em JSON e texto corrido), credencial e query string em URL, hex longo, número de 6+ dígitos, `*_id=` |
| **Bloqueia** | chave AWS, chave de service account GCP, PEM, connection string, string de alta entropia, `@` residual, texto acima de `max_chars`, `ner=True` sem o modelo instalado |

Regras próprias entram por `extra_masks` e `extra_blocks`. As padrão não podem ser removidas.

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

## Limites

- Nome em minúsculas ou fora de frase pode escapar: o modelo depende de contexto.
- Endereço exige logradouro **e** número. Cidade e bairro soltos passam.
- Número de 6+ dígitos sem separador vira `<N>`. Escreva métricas como `51.000.000` ou `51M`.
- Regex e NER não substituem minimização: não leve o dado pessoal se não precisar dele.

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
