import unittest,os,json

file_path = os.path.realpath(__file__)
file_dir = os.path.dirname(file_path)

from .symbol_parser import extract_names

class TestSymbolParser(unittest.TestCase):

    def test_parser(self):
        with open(os.path.join(file_dir, "test_symbol_parser.json"), 'r') as f:
            obj = json.load(f)
        for loc, cases in obj.items():
            for sym, res in cases:
                clz, method, sig = extract_names(sym)
                res = res.split(' ')
                if len(res) != 3:
                    res = (res[0], res[1], None)
                else:
                    res = tuple(res)
                self.assertEqual((clz, method, sig), res, f"Error in {loc} when parsing {sym}")

    def test_parser_full(self):
        test_case_full = os.path.join(file_dir, "test_symbol_parser_full.json")
        if not os.path.exists(test_case_full):
            print("Full test not exists, skip.")
            return
        with open(test_case_full, 'r') as f:
            obj = json.load(f)
        for loc, cases in obj.items():
            for sym, res in cases:
                clz, method, sig = extract_names(sym)
                res = res.split(' ')
                if len(res) != 3:
                    res = (res[0], res[1], None)
                else:
                    res = tuple(res)
                self.assertEqual((clz, method, sig), res, f"Error in {loc} when parsing {sym}")

if __name__ == '__main__':
    unittest.main()
