"""离线单元测试：不联网，用构造的响应头验证每一项检查和评分。运行: python3 -m unittest -v"""
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

import headers_check as hc

HERE = os.path.dirname(os.path.abspath(__file__))


def H(**kw):
    """H(strict_transport_security="...") -> Headers；下划线换成连字符。"""
    return hc.Headers([(k.replace("_", "-"), v) for k, v in kw.items()])


class TestParsing(unittest.TestCase):
    def test_case_insensitive_and_multi(self):
        h = hc.Headers([("Set-Cookie", "a=1"), ("set-cookie", "b=2"), ("X-Frame-Options", "DENY")])
        self.assertEqual(h.get_all("SET-COOKIE"), ["a=1", "b=2"])
        self.assertEqual(h.get("x-frame-options"), "DENY")
        self.assertIn("X-FRAME-OPTIONS", h)
        self.assertIsNone(h.get("missing"))

    def test_raw_headers_uses_last_response(self):
        text = ("HTTP/1.1 301 Moved\r\nLocation: https://x/\r\nX-Frame-Options: DENY\r\n\r\n"
                "HTTP/2 200\r\nserver: nginx\r\nx-content-type-options: nosniff\r\n")
        status, h = hc.parse_raw_headers(text)
        self.assertEqual(status, 200)
        self.assertEqual(h.get("x-content-type-options"), "nosniff")
        self.assertNotIn("X-Frame-Options", h)  # 来自跳转那一跳，不算

    def test_parse_csp_first_directive_wins(self):
        d = hc.parse_csp("default-src 'self'; script-src a.com; script-src *; ;")
        self.assertEqual(d["script-src"], ["a.com"])
        self.assertEqual(d["default-src"], ["'self'"])

    def test_normalize_url(self):
        self.assertEqual(hc.normalize_url("example.com"), "https://example.com")
        self.assertEqual(hc.normalize_url("http://a.b/x"), "http://a.b/x")
        with self.assertRaises(ValueError):
            hc.normalize_url("ftp://example.com")


class TestHSTS(unittest.TestCase):
    def check(self, value, https=True):
        h = H() if value is None else H(strict_transport_security=value)
        return hc.check_hsts(h, https)

    def test_missing(self):
        self.assertEqual(self.check(None).status, hc.FAIL)

    def test_http_site(self):
        f = self.check("max-age=31536000", https=False)
        self.assertEqual((f.status, f.score), (hc.FAIL, 0))

    def test_short_age(self):
        f = self.check("max-age=3600")
        self.assertEqual(f.status, hc.WARN)
        self.assertLess(f.score, f.max_score)

    def test_zero_and_garbage(self):
        self.assertEqual(self.check("max-age=0").status, hc.FAIL)
        self.assertEqual(self.check("includeSubDomains").status, hc.FAIL)

    def test_no_subdomains(self):
        f = self.check("max-age=31536000")
        self.assertEqual((f.status, f.score), (hc.WARN, 20))

    def test_full(self):
        f = self.check('max-age="63072000"; includeSubDomains; preload')
        self.assertEqual((f.status, f.score), (hc.PASS, 25))


class TestCSP(unittest.TestCase):
    def test_missing(self):
        self.assertEqual(hc.check_csp(H()).score, 0)

    def test_report_only(self):
        f = hc.check_csp(H(content_security_policy_report_only="default-src 'self'"))
        self.assertEqual((f.status, f.score), (hc.WARN, 5))

    def test_strict_policy_passes(self):
        f = hc.check_csp(H(content_security_policy=(
            "default-src 'self'; object-src 'none'; base-uri 'self'")))
        self.assertEqual(f.status, hc.PASS)

    def test_unsafe_inline(self):
        f = hc.check_csp(H(content_security_policy=(
            "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'")))
        self.assertIn("unsafe-inline", f.message)
        self.assertEqual(f.score, 15)

    def test_unsafe_inline_ignored_with_nonce(self):
        # 有 nonce 时现代浏览器忽略 'unsafe-inline'，那只是给老浏览器的回退
        f = hc.check_csp(H(content_security_policy=(
            "script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic' https:; "
            "object-src 'none'; base-uri 'none'")))
        self.assertEqual(f.status, hc.PASS)

    def test_no_script_restriction(self):
        f = hc.check_csp(H(content_security_policy="img-src 'self'"))
        self.assertEqual(f.status, hc.FAIL)
        self.assertGreaterEqual(f.score, 5)  # 有 CSP 至少给 5 分

    def test_wildcard(self):
        f = hc.check_csp(H(content_security_policy=(
            "default-src *; base-uri 'self'")))
        self.assertIn("过宽", f.message)
        self.assertIn("object-src", f.message)


class TestOtherHeaders(unittest.TestCase):
    def test_frame_options(self):
        self.assertEqual(hc.check_frame(H(x_frame_options="sameorigin")).status, hc.PASS)
        self.assertEqual(hc.check_frame(H(x_frame_options="ALLOW-FROM https://a")).status, hc.WARN)
        self.assertEqual(hc.check_frame(H(x_frame_options="yes")).status, hc.FAIL)
        self.assertEqual(hc.check_frame(H()).status, hc.FAIL)

    def test_frame_ancestors_replaces_xfo(self):
        f = hc.check_frame(H(content_security_policy="frame-ancestors 'none'"))
        self.assertEqual(f.status, hc.PASS)
        f = hc.check_frame(H(content_security_policy="frame-ancestors *", x_frame_options="DENY"))
        self.assertEqual(f.status, hc.FAIL)  # CSP 优先，* 等于没保护

    def test_nosniff(self):
        self.assertEqual(hc.check_nosniff(H(x_content_type_options="NoSniff")).status, hc.PASS)
        self.assertEqual(hc.check_nosniff(H(x_content_type_options="sniff")).status, hc.FAIL)

    def test_referrer(self):
        self.assertEqual(hc.check_referrer(H(referrer_policy="no-referrer")).status, hc.PASS)
        self.assertEqual(hc.check_referrer(H(referrer_policy="unsafe-url")).status, hc.FAIL)
        self.assertEqual(hc.check_referrer(H(referrer_policy="no-referrer-when-downgrade")).status,
                         hc.WARN)
        # 多个值时浏览器用最后一个认识的
        self.assertEqual(hc.check_referrer(
            H(referrer_policy="no-referrer, strict-origin-when-cross-origin")).status, hc.PASS)
        self.assertEqual(hc.check_referrer(H()).score, 5)

    def test_permissions(self):
        self.assertEqual(hc.check_permissions(H(permissions_policy="camera=()")).status, hc.PASS)
        self.assertEqual(hc.check_permissions(H(feature_policy="camera 'none'")).score, 5)
        self.assertEqual(hc.check_permissions(H()).score, 0)

    def test_coop(self):
        self.assertEqual(hc.check_coop(H(cross_origin_opener_policy="same-origin")).status, hc.PASS)
        self.assertEqual(hc.check_coop(H(cross_origin_opener_policy="unsafe-none")).score, 0)


class TestExtras(unittest.TestCase):
    def test_server_without_version_is_fine(self):
        self.assertEqual(hc.check_info_leaks(H(server="nginx")), [])
        leaks = hc.check_info_leaks(H(server="nginx/1.18.0", x_powered_by="Express"))
        self.assertEqual({f.header for f in leaks}, {"Server", "X-Powered-By"})

    def test_cookie_flags(self):
        good = hc.Headers([("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")])
        self.assertEqual(hc.check_cookies(good, True), [])
        bad = hc.Headers([("Set-Cookie", "sid=s3cr3tTOKEN; Path=/; SameSite=None")])
        [f] = hc.check_cookies(bad, True)
        self.assertIn("Secure", f.message)
        self.assertIn("HttpOnly", f.message)
        self.assertNotIn("s3cr3tTOKEN", f.value)  # Cookie 值不能出现在报告里

    def test_secure_not_required_on_http(self):
        h = hc.Headers([("Set-Cookie", "a=1; HttpOnly; SameSite=Strict")])
        self.assertEqual(hc.check_cookies(h, False), [])

    def test_deprecated(self):
        names = {f.header for f in hc.check_deprecated(
            H(x_xss_protection="1; mode=block", expect_ct="max-age=0"))}
        self.assertEqual(names, {"X-XSS-Protection", "Expect-CT"})
        self.assertEqual(hc.check_deprecated(H(x_xss_protection="0")), [])

    def test_https_redirect(self):
        self.assertEqual(len(hc.check_https_redirect("http://a", "http://a/")), 1)
        self.assertEqual(hc.check_https_redirect("http://a", "https://a/"), [])
        self.assertEqual(hc.check_https_redirect("https://a", "https://a/"), [])


class TestScoring(unittest.TestCase):
    def test_weights_sum_to_100(self):
        self.assertEqual(sum(hc.WEIGHTS.values()), 100)

    def test_grades(self):
        self.assertEqual(hc.grade_for(100), "A+")
        self.assertEqual(hc.grade_for(85), "A")
        self.assertEqual(hc.grade_for(70), "B")
        self.assertEqual(hc.grade_for(39), "F")

    def test_empty_headers_score(self):
        r = hc.analyze("https://a/", "https://a/", 200, H())
        self.assertEqual(r.score, 5)  # 只有 Referrer-Policy 缺失给的 5 分
        self.assertEqual(r.grade, "F")

    def test_penalty_cap_and_floor(self):
        cookies = [("Set-Cookie", f"c{i}=1") for i in range(20)]
        r = hc.analyze("https://a/", "https://a/", 200, hc.Headers(cookies))
        self.assertEqual(r.score, 0)  # 不会变成负数
        base = sum(f.score for f in r.findings if f.max_score)
        self.assertEqual(base - hc.PENALTY_CAP, -10)

    def test_example_files(self):
        with open(os.path.join(HERE, "examples", "strong.txt"), encoding="utf-8") as fh:
            status, h = hc.parse_raw_headers(fh.read())
        r = hc.analyze("https://s/", "https://s/", status, h)
        self.assertEqual((r.score, r.grade), (100, "A+"))
        with open(os.path.join(HERE, "examples", "weak.txt"), encoding="utf-8") as fh:
            status, h = hc.parse_raw_headers(fh.read())
        r = hc.analyze("https://w/", "https://w/", status, h)
        self.assertEqual(r.grade, "F")


class TestCLI(unittest.TestCase):
    def run_cli(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = hc.main(argv)
        return code, buf.getvalue()

    def test_file_json_and_fail_under(self):
        path = os.path.join(HERE, "examples", "weak.txt")
        code, out = self.run_cli(["-f", path, "--url", "https://w/", "--json", "--fail-under", "70"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data[0]["grade"], "F")
        self.assertNotIn("3f9a1c0d7e", out)  # Cookie 值被打码

    def test_fetch_is_mocked(self):
        fake = ("https://a.example/", 200, H(x_content_type_options="nosniff"))
        with mock.patch.object(hc, "fetch", return_value=fake) as m:
            code, out = self.run_cli(["a.example"])
        m.assert_called_once()
        self.assertEqual(m.call_args[0][0], "https://a.example")
        self.assertEqual(code, 0)
        self.assertIn("等级", out)

    def test_network_error(self):
        import urllib.error
        with mock.patch.object(hc, "fetch", side_effect=urllib.error.URLError("boom")):
            with mock.patch("sys.stderr", new=io.StringIO()):
                code, _ = self.run_cli(["a.example"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
