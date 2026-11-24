# HTTP Security Headers Checker

**English** | [简体中文](README.zh-CN.md)

A small Python CLI that requests a URL, checks the **security-related HTTP response
headers** it sends back (CSP, HSTS, X-Frame-Options and friends), gives the site a
**0–100 score and an A+ to F grade**, and tells you **how to fix** each problem.

It can also analyze headers offline: save the output of `curl -sI https://site` to a
file and pass it with `--file`.

Standard library only: no `pip install`. Python 3.8+.

## Usage

```bash
python3 headers_check.py example.com                  # no scheme → https://
python3 headers_check.py https://a.com http://b.com   # several sites at once
python3 headers_check.py example.com -v               # also print each header's raw value
python3 headers_check.py example.com --json           # machine-readable
python3 headers_check.py example.com --fail-under 70  # exit 1 if score < 70 (for CI)

curl -sI https://example.com > h.txt
python3 headers_check.py --file h.txt --url https://example.com   # offline
curl -sIL http://example.com | python3 headers_check.py -f - --url https://example.com

python3 -m unittest -v                                # offline tests
```

Example output for [`examples/weak.txt`](examples/weak.txt) (the CLI prints in Chinese;
shortened):

```
🔎 https://shop.example/
   得分 21/100   等级 F

 ⚠️  Strict-Transport-Security     12/25  max-age=86400（约 1 天），太短…
      👉 至少 15552000（180 天），推荐 31536000（1 年）
 ❌ Content-Security-Policy        5/25  脚本允许 'unsafe-inline'…；'unsafe-eval'…
 ⚠️  X-Frame-Options                5/15  ALLOW-FROM 已废弃，现代浏览器会忽略它
 ❌ X-Content-Type-Options         0/10  缺失…
 ⚠️  Set-Cookie: PHPSESSID            -2  缺少属性：Secure, HttpOnly, SameSite
 ⚠️  X-Powered-By                     -2  暴露了技术栈/版本号：PHP/7.4.3
 ℹ️  X-XSS-Protection                     1; mode=block：XSS Auditor 已被移除…
```

(`得分` = score, `等级` = grade, `缺失` = missing, `👉` lines are the fix advice.)
[`examples/strong.txt`](examples/strong.txt) scores 100/100 (A+).

| Exit code | Meaning |
|---|---|
| `0` | Done (and every score ≥ `--fail-under`, if given) |
| `1` | A score is below `--fail-under` |
| `2` | A request failed (bad URL, DNS, timeout, TLS error…) |

## What it checks and how it scores

Seven headers carry points, adding up to 100:

| Header | Points | Full marks when | What it protects against |
|---|---|---|---|
| `Strict-Transport-Security` | 25 | HTTPS, `max-age` ≥ 180 days, `includeSubDomains` | SSL stripping / downgrade to HTTP |
| `Content-Security-Policy` | 25 | restricts scripts, no `'unsafe-inline'` / `'unsafe-eval'` / `*` / `https:`, has `object-src` and `base-uri` | XSS, injected scripts |
| `X-Frame-Options` *or* CSP `frame-ancestors` | 15 | `DENY` / `SAMEORIGIN`, or `frame-ancestors` without `*` | clickjacking |
| `X-Content-Type-Options` | 10 | `nosniff` | MIME sniffing (an upload executed as a script) |
| `Referrer-Policy` | 10 | `no-referrer`, `same-origin`, `strict-origin(-when-cross-origin)` | leaking full URLs (tokens in query strings) to other sites |
| `Permissions-Policy` | 10 | present | iframes / scripts asking for camera, mic, location |
| `Cross-Origin-Opener-Policy` | 5 | `same-origin(-allow-popups)` | cross-window attacks (XS-Leaks, tabnabbing) |

Partial credit is given for weak but present settings: a short HSTS `max-age`, a CSP
with `'unsafe-inline'`, a CSP that's only `Report-Only`, the obsolete `ALLOW-FROM`, a
missing `Referrer-Policy` (modern browsers already default to a safe value).

Then extra checks **subtract 2 points each** (at most 15 in total, score never below 0):

- **Cookies** missing `Secure` (on HTTPS), `HttpOnly` or `SameSite`, or `SameSite=None`
  without `Secure`. Cookie **values are masked** in the report: they're often session tokens.
- **Version leaks**: `Server` with a version number (`nginx` alone is fine,
  `nginx/1.18.0` isn't), `X-Powered-By`, `X-AspNet-Version`, `X-Generator`.
- **No HTTP→HTTPS redirect** when you pass an `http://` URL (−4).

Deprecated headers (`X-XSS-Protection: 1`, `Expect-CT`, `Public-Key-Pins`) are reported as
info, with no penalty.

Grades: A+ ≥ 95, A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, otherwise F.

### Some details worth knowing

- **CSP and `'unsafe-inline'`**: if the script policy also has a `'nonce-…'` or
  `'sha256-…'` source, CSP2+ browsers ignore `'unsafe-inline'`; sites add it on purpose as a
  fallback for very old browsers. So it isn't counted against you in that case.
  Likewise `https:` is allowed next to `'strict-dynamic'`.
- **`frame-ancestors` beats `X-Frame-Options`**: when CSP has `frame-ancestors`, browsers
  ignore `X-Frame-Options`, so the checker looks at that first.
- **Referrer-Policy can list fallbacks** (`no-referrer, strict-origin-when-cross-origin`):
  the browser uses the last value it understands, and so does the checker.
- It sends a **GET** (not HEAD; some servers answer HEAD with different headers), follows
  redirects and grades the **final** response. 4xx/5xx pages are graded too: error pages
  should carry the headers as well.
- If a CSP directive appears twice, only the first counts, as in browsers.

## Limitations

- **One page, one request.** Headers can differ per path (an API, a login page, static
  files on a CDN). Check the pages that matter, not just the home page.
- **Headers are not the whole story.** A CSP full of allowed domains can still be bypassed
  through a JSONP endpoint or an old library on one of them; this tool checks the
  policy's syntax and common weak spots, not whether it can be bypassed. For that, use
  Google's [CSP Evaluator](https://csp-evaluator.withgoogle.com/).
- It doesn't check the TLS certificate or protocol versions, or HTML `<meta>` CSP tags.
- Headers set by JavaScript or a service worker aren't visible to it.
- The weights are an opinion, roughly following Mozilla Observatory and securityheaders.com.
  Change `WEIGHTS` if you disagree.

## Files
- `headers_check.py`: the CLI (header parsing → one check function per header → extras →
  score → report)
- `test_headers_check.py`: offline tests for every check, the scoring, the CLI, and that
  cookie values never appear in the output. Network calls are mocked.
- `examples/`: a weak and a strong set of headers to try with `--file`

## References
- OWASP HTTP Headers Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN, HTTP headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- Content Security Policy Level 3: https://www.w3.org/TR/CSP3/
- HSTS preload list requirements: https://hstspreload.org/
- Similar tools: [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory),
  [securityheaders.com](https://securityheaders.com/)
