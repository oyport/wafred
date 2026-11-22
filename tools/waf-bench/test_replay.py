"""Focused regression tests for raw HTTP fixture framing."""

import unittest

from replay import prepare


class PrepareTests(unittest.TestCase):
    def test_adds_byte_accurate_length_for_unframed_body(self):
        raw = b"POST /x HTTP/1.1\r\nHost: example.test\r\n\r\na=\xe4\xb8\xad"
        prepared = prepare(raw, None, None)
        head, body = prepared.split(b"\r\n\r\n", 1)
        self.assertEqual(body, b"a=\xe4\xb8\xad")
        self.assertIn(b"Content-Length: 5", head)

    def test_does_not_add_length_to_empty_body(self):
        prepared = prepare(
            b"GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n", None, None
        )
        head, _ = prepared.split(b"\r\n\r\n", 1)
        self.assertNotIn(b"Content-Length:", head)

    def test_preserves_existing_content_length_and_transfer_encoding(self):
        for framing in (b"Content-Length: 0", b"Transfer-Encoding: chunked"):
            with self.subTest(framing=framing):
                raw = (
                    b"POST /x HTTP/1.1\r\nHost: example.test\r\n"
                    + framing
                    + b"\r\n\r\nbody"
                )
                prepared = prepare(raw, None, None)
                head, _ = prepared.split(b"\r\n\r\n", 1)
                self.assertEqual(head.count(b"Content-Length:"), int(framing.startswith(b"Content-Length:")))
                self.assertEqual(head.count(b"Transfer-Encoding:"), int(framing.startswith(b"Transfer-Encoding:")))

    def test_trims_bytes_after_declared_request_body(self):
        raw = (
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\n"
            b"Content-Length: 4\r\n\r\nbody--\r\n"
        )
        prepared = prepare(raw, None, None)
        head, body = prepared.split(b"\r\n\r\n", 1)
        self.assertIn(b"Content-Length: 4", head)
        self.assertEqual(body, b"body")


if __name__ == "__main__":
    unittest.main()
