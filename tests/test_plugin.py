"""Region plugin: the "br" entry point is loaded by text-sanitizer-core. Needs the package installed."""
import importlib.metadata
import unittest

from text_sanitizer_br import MASKS, REGION, sanitize

try:
    importlib.metadata.distribution("text-sanitizer-br")
    INSTALLED = True
except importlib.metadata.PackageNotFoundError:
    INSTALLED = False


class Region(unittest.TestCase):
    def test_region_carries_the_brazilian_rules(self):
        self.assertEqual(REGION.name, "br")
        self.assertEqual(REGION.masks, MASKS)
        self.assertEqual(REGION.ner_model, "pt_core_news_sm")


@unittest.skipUnless(INSTALLED, "entry points exist only after pip install")
class Plugin(unittest.TestCase):
    def test_core_build_with_br_matches_the_package(self):
        from text_sanitizer_core import build

        text = "CPF 123.456.789-09, CEP 01310-100, fulano@example.com"
        self.assertEqual(build(["br"]).sanitize(text), sanitize(text))
        self.assertEqual(build(["br"]).sanitize(text)[0], "CPF <CPF>, CEP <CEP>, <EMAIL>")


if __name__ == "__main__":
    unittest.main()
