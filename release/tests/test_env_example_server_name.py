from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class EnvExampleServerName(unittest.TestCase):
    def test_init_refuses_the_shipped_server_name_placeholder(self):
        values = [line.split("=", 1)[1] for line in (ROOT / "env.example").read_text().splitlines()
                  if line.startswith("NETOPS_SERVER_NAME=")]
        self.assertEqual(len(values), 1)
        literal = 'PLACEHOLDER_NAME = "' + values[0] + '"\n'
        self.assertEqual((ROOT / "src/netops/init.py").read_text().count(literal), 1, literal)


if __name__ == "__main__":
    unittest.main()
