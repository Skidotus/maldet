"""The lowest risk level is stored as "Safe" but never shown as "Safe": a static
scan cannot prove a repository safe. Imports app.py and scanner.py, so
config.py must be importable; nothing here touches the network or database.
"""
import unittest

import app
import llm_summary
import scanner


class LevelLabelTests(unittest.TestCase):
    def test_only_safe_is_relabelled(self):
        self.assertEqual(scanner.level_label("Safe"), "Nothing found")
        for level in ("Low", "Medium", "High", "Critical", None):
            self.assertEqual(scanner.level_label(level), level)

    def test_stored_level_is_unchanged(self):
        """Thresholds, the database and the extension API all key on "Safe"."""
        self.assertEqual(scanner._level_for(0, (15, 35, 100)), "Safe")

    def test_templates_compile_and_use_the_filter(self):
        env = app.app.jinja_env
        self.assertEqual(env.filters["level_label"]("Safe"), "Nothing found")
        for name in ("detail.html", "index.html", "history.html", "report.html"):
            env.get_template(name)

    def test_badge_renders_the_label_but_keeps_the_css_class(self):
        with app.app.test_request_context():
            html = app.app.jinja_env.from_string(
                '<span class="seal-{{ l | lower }}">{{ l | level_label }}</span>').render(l="Safe")
        self.assertEqual(html, '<span class="seal-safe">Nothing found</span>')

    def test_summary_prompt_never_hands_the_model_the_word_safe_as_a_level(self):
        prompt = llm_summary._compose_prompt(
            "owner/repo", [], 0, {"level": "Safe", "score": 0}, {"level": "Safe", "score": 0})
        self.assertIn("Vulnerability risk: Nothing found", prompt)
        self.assertIn("Malicious-pattern risk: Nothing found", prompt)
        self.assertNotIn("risk: Safe", prompt)


if __name__ == "__main__":
    unittest.main()
