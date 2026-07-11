import unittest

from security_utils import is_safe_outbound_url


class SecurityUtilsTests(unittest.TestCase):
    def test_https_domain_allows_clash_fake_ip_range(self):
        safe, reason = is_safe_outbound_url(
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
            allow_proxy_dns=True,
        )
        if reason == "dns resolution failed: [Errno 8] nodename nor servname provided, or not known":
            self.skipTest("offline dns")
        # With Clash fake-ip this resolves to 198.18.x.x and must be allowed.
        self.assertTrue(safe, reason)

    def test_loopback_ip_literal_still_blocked(self):
        safe, reason = is_safe_outbound_url("https://127.0.0.1/v1")
        self.assertFalse(safe)
        self.assertIn("blocked", reason)

    def test_private_literal_still_blocked_without_allow_private(self):
        safe, _ = is_safe_outbound_url("http://192.168.1.10:11434/v1")
        self.assertFalse(safe)


if __name__ == "__main__":
    unittest.main()
