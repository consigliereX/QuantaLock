"""M6: offline tests for GUI-safe password composition and clipboard ownership."""
import unittest

from qpgen.gui_password_safety import (
    MAX_MEMORY_WORD, clipboard_fingerprint, clipboard_matches, compose_password
)


class GuiPasswordSafetyTests(unittest.TestCase):
    def test_empty_word_preserves_random_password(self):
        self.assertEqual(compose_password("RANDOM123!", ""), "RANDOM123!")

    def test_word_appended_without_erasing_random_component(self):
        self.assertEqual(compose_password("RANDOM123!", "alice"), "RANDOM123!alice")

    def test_oversized_word_never_replaces_full_password(self):
        with self.assertRaises(ValueError):
            compose_password("RANDOM123!", "X" * 33)

    def test_whitespace_removal_matches_prior_ui(self):
        self.assertEqual(compose_password("ABC", "  some word "), "ABCsomeword")

    def test_exact_max_memory_word(self):
        self.assertEqual(len(compose_password("ABC", "x" * MAX_MEMORY_WORD)), 35)

    def test_control_char_rejected(self):
        with self.assertRaises(ValueError):
            compose_password("ABC", "a\x00b")

    def test_invalid_random_component_rejected(self):
        with self.assertRaises(ValueError):
            compose_password("", "word")

    def test_clipboard_owned_match(self):
        tag = clipboard_fingerprint("strong random secret")
        self.assertTrue(clipboard_matches(tag, "strong random secret"))

    def test_clipboard_different_text_not_owned(self):
        tag = clipboard_fingerprint("strong random secret")
        self.assertFalse(clipboard_matches(tag, "newly copied notes"))

    def test_clipboard_empty_or_missing_token_not_owned(self):
        tag = clipboard_fingerprint("strong random secret")
        self.assertFalse(clipboard_matches(tag, ""))
        self.assertFalse(clipboard_matches(None, "strong random secret"))


if __name__ == "__main__":
    unittest.main()
