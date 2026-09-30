from __future__ import annotations

import unittest

from collectors.morgan import parse_combined_line


class MorganParserTests(unittest.TestCase):
    def test_valid_combined_line(self) -> None:
        line = '192.0.2.10 - - [30/Sep/2026:08:40:12 +0000] "GET /rest/products HTTP/1.1" 200 321 "-" "TestAgent/1.0"'
        event = parse_combined_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.event_type, "http_request")
        self.assertEqual(event.data["http_method"], "GET")
        self.assertEqual(event.data["response_status"], 200)
        self.assertEqual(event.data["response_size"], 321)
        self.assertFalse(event.data["sqli_suspected"])

    def test_query_values_are_removed_and_keys_extracted(self) -> None:
        secret_value = "highly-sensitive-value"
        line = f'192.0.2.10 - - [30/Sep/2026:08:40:12 +0000] "GET /rest/products/search?q={secret_value}&page=2 HTTP/1.1" 200 12 "-" "TestAgent"'
        event = parse_combined_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.data["path"], "/rest/products/search")
        self.assertTrue(event.data["query_present"])
        self.assertEqual(event.data["query_keys"], ["q", "page"])
        self.assertNotIn(secret_value, str(event.to_dict()))

    def test_sensitive_query_value_does_not_survive(self) -> None:
        line = '192.0.2.10 - - [30/Sep/2026:08:40:12 +0000] "POST /rest/user/login?password=do-not-store&token=also-secret HTTP/1.1" 401 99 "-" "TestAgent"'
        event = parse_combined_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        serialised = str(event.to_dict())
        self.assertNotIn("do-not-store", serialised)
        self.assertNotIn("also-secret", serialised)
        self.assertEqual(event.data["response_status"], 401)
        self.assertEqual(event.severity, "warning")

    def test_unusual_query_component_is_not_retained(self) -> None:
        line = '192.0.2.10 - - [30/Sep/2026:08:40:12 +0000] "GET /search?%27%20OR%201%3D1 HTTP/1.1" 200 1 "-" "TestAgent"'
        event = parse_combined_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.data["query_keys"], ["[unusual_key]"])
        self.assertTrue(event.data["sqli_suspected"])
        self.assertIn("boolean_expression", event.data["sqli_indicator_categories"])
        self.assertEqual(event.data["sqli_input_locations"], ["query"])
        self.assertNotIn("OR 1=1", str(event.to_dict()))

    def test_encoded_union_select_becomes_metadata_only(self) -> None:
        raw_value = "marker%27%20UNION%20SELECT%201--"
        line = (
            '192.0.2.10 - - [30/Sep/2026:08:40:12 +0000] '
            f'"GET /rest/products/search?q={raw_value} HTTP/1.1" 200 1 "-" "TestAgent"'
        )
        event = parse_combined_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertTrue(event.data["sqli_suspected"])
        self.assertEqual(event.data["query_keys"], ["q"])
        self.assertIn("union_select", event.data["sqli_indicator_categories"])
        self.assertIn("sql_comment", event.data["sqli_indicator_categories"])
        serialised = str(event.to_dict())
        self.assertNotIn(raw_value, serialised)
        self.assertNotIn("UNION SELECT 1", serialised)

    def test_sqli_in_path_is_replaced(self) -> None:
        raw_path = "/products/%27%20UNION%20SELECT%201--"
        line = (
            '192.0.2.10 - - [30/Sep/2026:08:40:12 +0000] '
            f'"GET {raw_path} HTTP/1.1" 404 1 "-" "TestAgent"'
        )
        event = parse_combined_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.data["path"], "/[REDACTED_SQLI_INPUT]")
        self.assertEqual(event.data["sqli_input_locations"], ["path"])
        self.assertNotIn(raw_path, str(event.to_dict()))

    def test_secret_like_path_segment_is_redacted(self) -> None:
        line = '192.0.2.10 - - [30/Sep/2026:08:40:12 +0000] "GET /reset/token/path-secret-value HTTP/1.1" 200 1 "-" "TestAgent"'
        event = parse_combined_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.data["path"], "/reset/token/[REDACTED]")
        self.assertNotIn("path-secret-value", str(event.to_dict()))

    def test_malformed_line_is_ignored(self) -> None:
        self.assertIsNone(parse_combined_line("not a combined log line"))


if __name__ == "__main__":
    unittest.main()
