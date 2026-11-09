"""Independent standard-library tests; no Qiskit installation required."""
import unittest
from dataclasses import dataclass
from unittest.mock import patch

from qpgen import generate_password, QuantumPassConfig
from qpgen.secure_password import secure_password


class SecurePasswordTests(unittest.TestCase):
    def test_expected_length_and_characters(self):
        cfg = QuantumPassConfig(password_length=50, alphabet="abC123!@")
        result = generate_password(cfg)
        self.assertEqual(len(result), 50)
        self.assertLessEqual(set(result), set(cfg.alphabet))

    def test_public_entrypoint_uses_secure_path(self):
        cfg = QuantumPassConfig(password_length=12, alphabet="AB")
        with patch("qpgen.secure_password.secrets.choice", side_effect=lambda seq: seq[0]) as choice:
            self.assertEqual(generate_password(cfg), "A" * 12)
            self.assertEqual(choice.call_count, 12)

    def test_empty_duplicate_and_single_character_alphabets_rejected(self):
        for alphabet in ("", "A", "AAB"):
            with self.subTest(alphabet=alphabet):
                with self.assertRaises(ValueError):
                    secure_password(QuantumPassConfig(alphabet=alphabet))

    def test_invalid_lengths_rejected(self):
        for length in (0, 7, 129, -1, 12.0, True):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    secure_password(QuantumPassConfig(password_length=length))

    def test_default_config_works(self):
        self.assertEqual(len(generate_password()), 20)


if __name__ == "__main__":
    unittest.main()
