"""Person names (extra "ner"). All names are fictitious."""
import importlib.util
import unittest

from text_sanitizer_br import Sanitizer

HAS_MODEL = importlib.util.find_spec("spacy") is not None and importlib.util.find_spec("pt_core_news_sm") is not None


class FailSecure(unittest.TestCase):
    def test_missing_model_blocks_everything(self):
        clean, report = Sanitizer(ner=True, ner_model="modelo_que_nao_existe").sanitize("texto sem nada")
        self.assertEqual(clean, "")
        self.assertTrue(report.blocked and report.blocked[0].startswith("ner_unavailable"), report.blocked)

    def test_off_by_default(self):
        clean, report = Sanitizer().sanitize("O cliente João da Silva Pereira ligou")
        self.assertIn("João", clean)
        self.assertTrue(report.ok)


@unittest.skipUnless(HAS_MODEL, 'needs pip install "text-sanitizer-br[ner]"')
class Names(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Sanitizer(ner=True)

    def test_person_names_masked(self):
        for text, leaked in [("O cliente João da Silva Pereira reclamou do atendimento", "João"),
                             ("Falei com a Maria Fernanda ontem sobre o carro", "Fernanda"),
                             ("o comprador Carlos Eduardo Souza arrematou o lote", "Souza"),
                             ("Ligação da Ana Paula Ribeiro, da concessionária", "Ribeiro")]:
            with self.subTest(text=text):
                clean, report = self.s.sanitize(text)
                self.assertIn("<PERSON>", clean)
                self.assertNotIn(leaked, clean)
                self.assertTrue(report.ok)

    def test_names_and_regex_together(self):
        clean, _ = self.s.sanitize("João da Silva, CPF 123.456.789-09, fulano@example.com")
        for leaked in ("João", "123.456", "fulano@"):
            self.assertNotIn(leaked, clean)

    def test_technical_text_untouched(self):
        for text in ("p95 624 s; 51.000.000 rows; 2026-09-27",
                     "erro SQLSTATE[HY000] Connection timed out na Vendas Concluídas",
                     "deploy do b2b-adm falhou no Cloud Run"):
            with self.subTest(text=text):
                self.assertEqual(self.s.sanitize(text)[0], text)


if __name__ == "__main__":
    unittest.main()
