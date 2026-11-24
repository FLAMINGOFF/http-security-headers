# HTTP 安全响应头检查器 (HTTP Security Headers Checker)

[English](README.md) | **简体中文**

一个小巧的 Python 命令行工具：请求一个网址，检查返回的**安全相关 HTTP 响应头**
（CSP、HSTS、X-Frame-Options 等），给网站打一个 **0–100 分、A+ 到 F 的等级**，
并告诉你每个问题**该怎么修**。

也可以离线分析：把 `curl -sI https://网站` 的输出存成文件，用 `--file` 读入。

只用标准库，不需要 `pip install`。需要 Python 3.8+。

## 用法

```bash
python3 headers_check.py example.com                  # 不写协议默认 https://
python3 headers_check.py https://a.com http://b.com   # 一次检查多个网站
python3 headers_check.py example.com -v               # 同时显示每个头的原始值
python3 headers_check.py example.com --json           # 机器可读的输出
python3 headers_check.py example.com --fail-under 70  # 低于 70 分退出码为 1（适合 CI）

curl -sI https://example.com > h.txt
python3 headers_check.py --file h.txt --url https://example.com   # 离线分析
curl -sIL http://example.com | python3 headers_check.py -f - --url https://example.com

python3 -m unittest -v                                # 离线测试
```

[`examples/weak.txt`](examples/weak.txt) 的输出示例（节选）：

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

`👉` 开头的行是修复建议。[`examples/strong.txt`](examples/strong.txt) 是 100 分（A+）。

| 退出码 | 含义 |
|---|---|
| `0` | 完成（如果给了 `--fail-under`，所有得分都达标） |
| `1` | 有网址得分低于 `--fail-under` |
| `2` | 请求失败（网址错误、DNS、超时、TLS 错误…） |

## 检查什么、怎么打分

7 个响应头计分，总分 100：

| 响应头 | 分值 | 满分条件 | 防的是什么 |
|---|---|---|---|
| `Strict-Transport-Security` | 25 | HTTPS，`max-age` ≥ 180 天，带 `includeSubDomains` | SSL 剥离、降级到 HTTP |
| `Content-Security-Policy` | 25 | 限制了脚本来源，没有 `'unsafe-inline'` / `'unsafe-eval'` / `*` / `https:`，有 `object-src` 和 `base-uri` | XSS、注入的脚本 |
| `X-Frame-Options` *或* CSP `frame-ancestors` | 15 | `DENY` / `SAMEORIGIN`，或不含 `*` 的 `frame-ancestors` | 点击劫持 |
| `X-Content-Type-Options` | 10 | `nosniff` | MIME 嗅探（上传的文件被当成脚本执行） |
| `Referrer-Policy` | 10 | `no-referrer`、`same-origin`、`strict-origin(-when-cross-origin)` | 把完整 URL（含查询参数里的 token）泄露给其他网站 |
| `Permissions-Policy` | 10 | 已设置 | iframe / 脚本申请摄像头、麦克风、定位 |
| `Cross-Origin-Opener-Policy` | 5 | `same-origin(-allow-popups)` | 跨窗口攻击（XS-Leaks、Tabnabbing） |

设置了但不够好的给部分分：HSTS `max-age` 太短、CSP 带 `'unsafe-inline'`、CSP 只有
`Report-Only`、已废弃的 `ALLOW-FROM`、缺 `Referrer-Policy`（现代浏览器默认值已经比较安全）。

然后附加检查**每项扣 2 分**（最多扣 15 分，总分不会低于 0）：

- **Cookie** 缺 `Secure`（HTTPS 下）、`HttpOnly` 或 `SameSite`，或者 `SameSite=None` 却没有
  `Secure`。报告里 Cookie 的**值会被打码**：它们经常是会话令牌。
- **版本号泄露**：带版本号的 `Server`（只写 `nginx` 没问题，`nginx/1.18.0` 扣分）、
  `X-Powered-By`、`X-AspNet-Version`、`X-Generator`。
- 传入 `http://` 网址时**没有跳转到 HTTPS**（扣 4 分）。

已废弃的响应头（`X-XSS-Protection: 1`、`Expect-CT`、`Public-Key-Pins`）只作提示，不扣分。

等级：A+ ≥ 95，A ≥ 85，B ≥ 70，C ≥ 55，D ≥ 40，其余为 F。

### 几个值得知道的细节

- **CSP 和 `'unsafe-inline'`**：如果脚本策略里同时有 `'nonce-…'` 或 `'sha256-…'`，支持
  CSP2 及以上的浏览器会忽略 `'unsafe-inline'`，网站是故意加上它给老浏览器做回退的，
  所以这种情况不扣分。同理，和 `'strict-dynamic'` 一起出现的 `https:` 也不扣分。
- **`frame-ancestors` 优先于 `X-Frame-Options`**：CSP 有 `frame-ancestors` 时浏览器会忽略
  `X-Frame-Options`，所以检查器先看它。
- **Referrer-Policy 可以写多个回退值**（`no-referrer, strict-origin-when-cross-origin`）：
  浏览器用最后一个它认识的，检查器也一样。
- 发送的是 **GET**（不是 HEAD，有些服务器对 HEAD 返回的头不一样），会跟随跳转，评的是
  **最终**响应。4xx/5xx 页面照样评分：错误页也应该带安全头。
- CSP 里同一个指令出现两次时只认第一个，与浏览器一致。

## 局限性

- **一个页面、一次请求。** 不同路径的响应头可能不同（API、登录页、CDN 上的静态文件）。
  重要的页面都要查，不要只查首页。
- **响应头不是全部。** 允许了很多域名的 CSP，仍可能通过其中某个域名上的 JSONP 接口或旧版本库
  被绕过；本工具检查的是策略语法和常见弱点，不判断能否被绕过。这方面可以用 Google 的
  [CSP Evaluator](https://csp-evaluator.withgoogle.com/)。
- 不检查 TLS 证书和协议版本，也不看 HTML 里 `<meta>` 写的 CSP。
- 由 JavaScript 或 Service Worker 设置的头它看不到。
- 分值权重是一种观点，大致参考 Mozilla Observatory 和 securityheaders.com。不同意的话改
  `WEIGHTS` 即可。

## 文件
- `headers_check.py`：命令行工具（解析响应头 → 每个头一个检查函数 → 附加检查 → 评分 → 报告）
- `test_headers_check.py`：离线测试，覆盖每一项检查、评分、命令行，并确认 Cookie 的值不会出现在输出里。网络请求都是模拟的。
- `examples/`：一组较差、一组较好的响应头，可以用 `--file` 试试

## 参考资料
- OWASP HTTP Headers Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- MDN HTTP 响应头: https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers
- Content Security Policy Level 3: https://www.w3.org/TR/CSP3/
- HSTS preload 列表要求: https://hstspreload.org/
- 类似工具: [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory),
  [securityheaders.com](https://securityheaders.com/)
