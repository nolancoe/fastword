import unittest
from fastword.utils import generate_password

class TestPasswordGenerator(unittest.TestCase):
    def test_default_length(self):
        pwd = generate_password()
        self.assertEqual(len(pwd), 16)

    def test_custom_length(self):
        pwd = generate_password(length=32)
        self.assertEqual(len(pwd), 32)

    def test_empty_charset(self):
        with self.assertRaises(ValueError):
            generate_password(
                use_uppercase=False,
                use_lowercase=False,
                use_digits=False,
                use_symbols=False
            )

if __name__ == '__main__':
    unittest.main()