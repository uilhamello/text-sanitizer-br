"""Plugin contract: the "br" entry point builds a working sanitizer. Needs the package installed."""
import importlib.metadata
import unittest

try:
    importlib.metadata.distribution("text-sanitizer-br")
    INSTALLED = True
except importlib.metadata.PackageNotFoundError:
    INSTALLED = False


@unittest.skipUnless(INSTALLED, "entry points exist only after pip install")
class Plugin(unittest.TestCase):
    def test_br_entry_point_follows_the_contract(self):
        eps = {ep.name: ep for ep in importlib.metadata.entry_points(group="text_sanitizers")}
        factory = eps["br"].load()
        s = factory(max_chars=100, extra_masks=[], extra_blocks=[], ner=False)
        clean, report = s.sanitize("CPF 123.456.789-09")
        self.assertEqual(clean, "CPF <CPF>")
        self.assertEqual(report.masks, {"cpf": 1})
        self.assertEqual(report.blocked, [])


if __name__ == "__main__":
    unittest.main()
