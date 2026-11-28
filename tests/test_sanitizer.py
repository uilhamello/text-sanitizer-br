"""All data here is fictitious."""
import time
import unittest

from text_sanitizer_br import Sanitizer, sanitize


class Masks(unittest.TestCase):
    CASES = [
        ("cliente fulano@example.com reclamou", "<EMAIL>", "fulano@"),
        ("CPF 123.456.789-09 no cadastro", "<CPF>", "123.456"),
        ("CNPJ 12.345.678/0001-95", "<CNPJ>", "0001"),
        ("CPF sem máscara 12345678909", "<N>", "12345678909"),
        ("placa ABC1D23 e ABC-1234", "<PLATE>", "ABC1D23"),
        ("fone (11) 91234-5678", "<PHONE>", "91234"),
        ("origem 10.0.0.7 porta 6033", "<IP>", "10.0.0.7"),
        ("GET https://api.example.com/x?token=abc&id=9", "?<QUERY>", "token=abc"),
        ("senha=Hunter2 e password: 'x y'", "<SECRET>", "Hunter2"),
        ("Authorization: Bearer abcDEF123456789xyz", "<SECRET>", "abcDEF"),  # whole header since auth_header
        ("cookie SID=deadbeef1234", "<SECRET>", "deadbeef"),
        ("SECRET_KEY='django-insecure-fake0a1b2c'", "<SECRET>", "fake0a1b2c"),  # _KEY suffix since core v0.2.2
        ("id_empresa=48213 e user_id: 77", "id_empresa=<N>", "48213"),
        ("req 3f2b8c1e-9a4d-4e6f-8b2a-1c3d5e7f9a0b", "<UUID>", "3f2b8c1e"),
        ("jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4", "<JWT>", "eyJhbGci"),
        ('{"password": "hunter2", "api_key": "k1"}', '"password": <SECRET>', "hunter2"),
        ("{'senha': 'Hunter2'}", "<SECRET>", "Hunter2"),
        ("a senha é hunter2", "senha é <SECRET>", "hunter2"),
        ("o token de acesso ficou Abc123xyz", "<SECRET>", "Abc123xyz"),
        ("http://admin:s3cret@192.168.0.1/admin", "<USERINFO>@<IP>", "s3cret"),
        ("https://admin:s3cret@db.internal/x", "<USERINFO>@db.internal", "s3cret"),
        ("cartão 4111 1111 1111 1111 recusado", "<CARD>", "1111"),
        ("cartão 4111-1111-1111-1111", "<CARD>", "4111"),
        ("amex 3782 822463 10005", "<CARD>", "822463"),
        ("fone (11) 98765 4321", "<PHONE>", "98765"),
        ("placa abc1d23 apreendida", "<PLATE>", "abc1d23"),
        # Fake tokens built at runtime so secret scanners (e.g. GitHub push protection) do not flag the source.
        ("slack " + "xox" + "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", "<TOKEN>", "AbCdEf"),
        ("use " + "gh" + "p_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5 no CI", "<TOKEN>", "p_aB3dE5"),
        ("stripe " + "sk" + "_live_51HxYzAbCdEfGhIjKlMnOpQr", "<TOKEN>", "_live_"),
        ("Mora na Rua Augusta, 1500, apto 42, São Paulo", "Mora na <ADDRESS>, São Paulo", "Augusta"),
        ("entrega na Av. Paulista 1000", "<ADDRESS>", "Paulista"),
        ("Travessa das Flores, nº 12, casa 3", "<ADDRESS>", "Flores"),
        ("RG 12.345.678-9 e 1.234.567-X", "<RG>", "345.678"),
        ("CEP 01310-100", "<CEP>", "01310"),
    ]

    def test_digits_failing_luhn_are_not_a_card(self):
        clean, _ = sanitize("pedido 1234 5678 9012 3456")
        self.assertNotIn("<CARD>", clean)

    def test_masks(self):
        for text, expected, leaked in self.CASES:
            with self.subTest(text=text):
                clean, report = sanitize(text)
                self.assertIn(expected, clean)
                self.assertNotIn(leaked, clean)
                self.assertTrue(report.ok, report.blocked)


class Leaks(unittest.TestCase):
    """Leaks found by the dry-run of 2026-10-15. All data is fictitious."""
    CASES = [
        ("CPF 123 456 789 09 inválido", "456 789"),
        # Third pass: IDs and logins.
        ("usuario: fulano.silva", "fulano"),
        ("participante=4521", "4521"),
        ("cod_usuario=4521", "4521"),
        ("/usuarios/4521/editar", "4521"),
        # Fourth pass: names, stores and addresses without the usual cues.
        ('{"nome":"FULANO DE TAL"}', "FULANO"),
        ("cliente Fulano reclamou", "Fulano"),
        ("Att, Fulano", "Fulano"),
        ("Atendente: Beltrana", "Beltrana"),
        ("Concessionária: Auto Exemplo Veículos", "Exemplo"),
        ("loja: Auto Exemplo Veículos", "Exemplo"),
        ("Auto Exemplo ME", "Exemplo"),
        ("| 312 | Auto Exemplo Veículos | SP |", "Exemplo"),
        ("na Auto Exemplo Veículos", "Exemplo"),
        ("Exemplo Brasil Comércio de Veículos", "Exemplo"),
        ("R. das Flores, s/n", "Flores"),
        ("endereço: Flores, 150 - Centro", "Flores"),
        ("Rua 7 de Setembro, 150", "Setembro"),
        ("logradouro: Rua das Flores", "Flores"),
        # Greeting, line start and "Surname, <PERSON>" (needed no matter which name the model knows).
        ("Prezado Fulano,", "Fulano"),
        ("Oi Fulano, tudo bem", "Fulano"),
        ("Beltrana ligou ontem", "Beltrana"),
        # Second adversarial pass (documents).
        ("CPF 111.444.777/35", "444.777"),
        ("cpf=111.444.77735", "77735"),
        ("CNPJ 11.222.333.0001-81", "0001"),
        ("emitente 11.222.333.0001-81", "0001"),
        ("tel +55 11 98765.4321", "98765"),
        ("tel 98765-4321", "98765"),
        ("ligar 98765-4321 amanhã", "98765"),
        ("whats 11-98765-4321", "98765"),
        ("placa ABC.1D23", "1D23"),
        ("placa abc 1234", "abc 1234"),
        ("CEP 01.310-100", "310-100"),
        ("entrega em 01.310-100", "310-100"),
        ("cartão final 1111 validade 12/29", "12/29"),
        ("CNPJ 12 345 678 0001 95", "0001"),
        ("RG 12 345 678 9", "345 678"),
        ("CPF: 123-456-789-09", "456-789"),
        ("CEP 01310 100", "01310"),
        ("+55 11 9 8765-4321", "8765"),
        ("CPF 123.456.789 09", "456.789"),
        ("placa ABC 1D23 apreendida", "ABC 1D23"),
        ("chassi 9BWZZZ377VT004251", "377VT"),
        ("usuário 4521 e loja 312 no pedido 98765", "4521"),
        ("usuário 4521 e loja 312 no pedido 98765", " 312"),
        ("anunciante nº 4521", "4521"),
        ("avaliação #20431 travada", "20431"),
        ("a loja Auto Center Paulista reclamou", "Paulista"),
        ("concessionária Horizonte Veículos ligou", "Horizonte"),
        ("emitido por Veículos Horizonte Ltda", "Horizonte"),
        ("Comercial Estrela S.A. pagou", "Estrela"),
        ("o Rodrigo reclamou do boleto", "Rodrigo"),
        ("Falei com a Patrícia ontem", "Patrícia"),
        ("Sr. Rodrigo Almeida aguarda", "Almeida"),
        ("contato fulano (arroba) example (ponto) com", "fulano"),
        ("RG MG-12.345.678", "12.345.678"),
        ("agência 1234 conta 56789-0", "56789-0"),
        ("agência: 1234-5 conta corrente 12345-6", "12345-6"),
        ("fulano.silva @ example.com.br", "fulano.silva"),
        ("renavam 12345678901 bytes", "12345678901"),
    ]

    def test_no_leak(self):
        for text, leaked in self.CASES:
            with self.subTest(text=text):
                clean, report = sanitize(text)
                self.assertNotIn(leaked, clean)
                self.assertTrue(report.ok, report.blocked)

    def test_false_positives_kept(self):
        for text in ("o Redis caiu às 10:30", "em 2024 o deploy caiu 3 vezes", "a loja recebeu 3 lances",
                     "loja virtual fora do ar", "erro 500 no pedido de compra", "a senha do usuário expirou",
                     "a Cloudflare respondeu 520", "o deploy rodou na versão 5.6",
                     "CPF inválido no cadastro", "placa não encontrada", "tel vazio", "cartão final 1111",
                     "usuário: inválido", "login: não autorizado", "config.yaml por config.yml",
                     "Lista de Veículos vazia", "API Busca Veículos", "Google Cloud Serviços", "DEPLOY ME AGORA",
                     "endereço: inválido", "endereço: null", "Rua sem saída", "Att, equipe",
                     '"name": "Cloud Run Service"', "Comércio de Veículos",
                     "Olá Mundo!", "Hello World.", "Dear Sir,", "Bom dia Pessoal,", "Sentry avisou 3 vezes",
                     "Oi, tudo bem?", "Av. média de 150 ms", "o Cloud Run quer mais memória"):
            with self.subTest(text=text):
                self.assertEqual(sanitize(text)[0], text)


class ExtraMasks(unittest.TestCase):
    def test_readme_example(self):
        """The README example: a ticket shaped like an old plate (TCK-4521) must come out as <TICKET>."""
        s = Sanitizer(extra_masks=[("ticket", r"\bTCK-\d+\b", "<TICKET>")])
        self.assertEqual(s.sanitize("TCK-4521 aberto")[0], "<TICKET> aberto")


class Blocks(unittest.TestCase):
    CASES = [
        ("aws AKIAABCDEFGHIJKLMNOP", "aws_key"),
        ('{"private_key": "x"}', "gcp_key"),
        ("-----BEGIN CERTIFICATE-----", "pem_header"),
        ("dsn mysql://root@db/app", "conn_string"),
        ("dsn mysql://root:pw@db/app", "conn_string"),
        ("loose aZ9kQ2xP7mL4vB8nR3tY6wE1", "high_entropy"),
        ("x" * 20001, "too_long>20000"),
        (None, "not_text"),
    ]

    def test_blocks(self):
        for text, reason in self.CASES:
            with self.subTest(reason=reason):
                self.assertIn(reason, sanitize(text)[1].blocked)

    def test_oversized_input_is_blocked_before_the_regexes(self):
        start = time.monotonic()
        clean, report = sanitize("x@" * 100000)  # took ~20 s when the size check ran last
        self.assertLess(time.monotonic() - start, 1)
        self.assertEqual(clean, "")
        self.assertIn("too_long>20000", report.blocked)


class KeepsMetrics(unittest.TestCase):
    def test_metrics_untouched(self):
        text = "p95 624 s; CPU 1-3%; Rows_examined 30M-51M; 51.000.000 rows; 180 conns; 17:30-18:05; latency=310ms; 2026-09-27"
        clean, report = sanitize(text)
        self.assertEqual(clean, text)
        self.assertTrue(report.ok)

    def test_secret_words_without_value_untouched(self):
        for text in ("auth failed for user", "session timeout 30s", "cookie expirado", "token inválido"):
            with self.subTest(text=text):
                self.assertEqual(sanitize(text)[0], text)

    def test_words_that_look_like_streets_untouched(self):
        # "avaliação 2026" is now an id (id_word); "de" keeps the street-rule check without that ambiguity.
        for text in ("a avaliação de 2026 subiu", "rodando 3 réplicas", "estradas ruins", "via API 2"):
            with self.subTest(text=text):
                self.assertEqual(sanitize(text)[0], text)

    def test_error_messages_untouched(self):
        text = "SQLSTATE[HY000] [2002] Connection timed out; Waiting for table metadata lock"
        self.assertEqual(sanitize(text)[0], text)


class Extensible(unittest.TestCase):
    def test_extra_patterns(self):
        s = Sanitizer(extra_masks=[("ticket", r"\bTCK-\d+\b", "<TICKET>")], extra_blocks=[("internal", r"(?i)confidencial")])
        clean, report = s.sanitize("TCK-42 aberto")
        self.assertEqual(clean, "<TICKET> aberto")
        self.assertIn("internal", s.sanitize("doc CONFIDENCIAL")[1].blocked)


if __name__ == "__main__":
    unittest.main()
