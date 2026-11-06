"""Negative transport checks at the public Ollama and Tattler seams."""
import io
import json
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from obsession_lab.ollama_bridge import OllamaClient
from obsession_lab.opportunity_bridge import fetch_tattler_current


class MemoryOpener:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request.full_url, timeout))
        return io.BytesIO(self.reply)


class LoopbackTransportTests(unittest.TestCase):
    def assert_safe_handlers(self, build):
        handlers = build.call_args.args
        proxy = [h for h in handlers if isinstance(h, urllib.request.ProxyHandler)]
        self.assertEqual(1, len(proxy))
        self.assertEqual({}, proxy[0].proxies)
        redirects = [h for h in handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
        self.assertEqual(1, len(redirects))
        req = urllib.request.Request('http://127.0.0.1:11434/api/chat')
        with self.assertRaises(urllib.error.HTTPError):
            redirects[0].redirect_request(req, None, 302, 'Found', {}, 'https://external.invalid/secret')

    def test_fixed_endpoint_and_method_allowlist(self):
        from obsession_lab.loopback_http import open_fixed_loopback
        bad = [
            urllib.request.Request('http://127.0.0.1:11434/api/chat', method='GET'),
            urllib.request.Request('http://127.0.0.1:11434/other', method='POST'),
            urllib.request.Request('http://127.0.0.2:11434/api/chat', method='POST'),
            urllib.request.Request('https://external.invalid/api/chat', method='POST'),
        ]
        with patch('urllib.request.build_opener') as build:
            for req in bad:
                with self.subTest(url=req.full_url), self.assertRaises(ValueError):
                    open_fixed_loopback(req, timeout=3)
            build.assert_not_called()

    def test_ollama_does_not_use_ambient_proxy_or_follow_redirect(self):
        body = json.dumps({'model':'qwen3:4b-instruct','done':True,'done_reason':'stop',
            'message':{'role':'assistant','content':'Synthetic answer'}}).encode()
        opener = MemoryOpener(body)
        with patch('urllib.request.urlopen', side_effect=AssertionError('unsafe default opener')), \
             patch('urllib.request.build_opener', return_value=opener) as build:
            reply = OllamaClient(allow_live=True).chat('qwen3:4b-instruct',
                [{'role':'user','content':'Synthetic'}])
        self.assertEqual('Synthetic answer', reply.text)
        self.assertEqual([('http://127.0.0.1:11434/api/chat', 75)], opener.calls)
        self.assert_safe_handlers(build)

    def test_tattler_does_not_use_ambient_proxy_or_follow_redirect(self):
        opener = MemoryOpener(b'[]')
        with patch('urllib.request.urlopen', side_effect=AssertionError('unsafe default opener')), \
             patch('urllib.request.build_opener', return_value=opener) as build:
            records = fetch_tattler_current()
        self.assertEqual([], records)
        self.assertEqual([('http://127.0.0.1:9147/api/v1/current', 3)], opener.calls)
        self.assert_safe_handlers(build)


if __name__ == '__main__':
    unittest.main()
