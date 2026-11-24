#!/usr/bin/env python3
"""
HTTP 安全响应头检查器 (HTTP Security Headers Checker)

输入一个网址，请求一次，检查返回的安全相关响应头：
CSP、HSTS、X-Frame-Options、X-Content-Type-Options、Referrer-Policy、
Permissions-Policy、Cross-Origin-Opener-Policy，再加上几项附加检查
（Cookie 属性、版本号泄露、过时的响应头、HTTP→HTTPS 跳转）。
最后给出 0–100 分、A+ 到 F 的等级，以及每一项的修复建议。

也可以离线分析：把 `curl -sI https://example.com` 的输出存成文件，用 --file 读入。

只依赖 Python 标准库，Python 3.8+ 可直接运行。
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

USER_AGENT = "http-security-headers-checker (learning project)"

PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"
ICONS = {PASS: "✅", WARN: "⚠️ ", FAIL: "❌", INFO: "ℹ️ "}

# 各项满分，加起来 100
WEIGHTS = {
    "Strict-Transport-Security": 25,
    "Content-Security-Policy": 25,
    "X-Frame-Options": 15,
    "X-Content-Type-Options": 10,
    "Referrer-Policy": 10,
    "Permissions-Policy": 10,
    "Cross-Origin-Opener-Policy": 5,
}
PENALTY_EACH = 2   # 每个附加问题（Cookie、版本泄露）扣的分
PENALTY_CAP = 15   # 附加问题最多扣这么多

GRADES = [(95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]

HSTS_MIN_AGE = 15552000  # 180 天，主流扫描器的推荐下限
HSTS_PRELOAD_AGE = 31536000  # 1 年，hstspreload.org 的要求


@dataclass
class Finding:
    header: str
    status: str          # pass / warn / fail / info
    score: int           # 这一项得到的分（附加检查为负数=扣分）
    max_score: int       # 这一项满分（附加检查为 0）
    message: str         # 现状
    advice: str = ""     # 怎么修
    value: Optional[str] = None


@dataclass
class Report:
    url: str
    final_url: str
    status_code: Optional[int]
    findings: List[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        base = sum(f.score for f in self.findings if f.max_score > 0)
        penalty = -sum(f.score for f in self.findings if f.max_score == 0)
        return max(0, base - min(penalty, PENALTY_CAP))

    @property
    def grade(self) -> str:
        return grade_for(self.score)


def grade_for(score: int) -> str:
    for threshold, letter in GRADES:
        if score >= threshold:
            return letter
    return "F"


# ---------------------------------------------------------------- 响应头容器

class Headers:
    """大小写不敏感、保留重复项（Set-Cookie 会出现多次）的响应头集合。"""

    def __init__(self, pairs: List[Tuple[str, str]]):
        self._items: Dict[str, List[str]] = {}
        for name, value in pairs:
            self._items.setdefault(name.strip().lower(), []).append(value.strip())

    def get(self, name: str) -> Optional[str]:
        values = self._items.get(name.lower())
        if not values:
            return None
        # 同名头出现多次时，浏览器对大部分安全头只认第一个；这里合并后交给检查函数
        return ", ".join(values)

    def get_all(self, name: str) -> List[str]:
        return list(self._items.get(name.lower(), []))

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._items


def parse_raw_headers(text: str) -> Tuple[Optional[int], Headers]:
    """解析 `curl -sI` 风格的文本。有多个响应（跟随了跳转）时只取最后一个。"""
    blocks: List[List[str]] = [[]]
    for line in text.splitlines():
        if line.upper().startswith("HTTP/"):
            blocks.append([line])
        elif line.strip():
            blocks[-1].append(line)
    block = next((b for b in reversed(blocks) if b), [])
    status = None
    pairs = []
    for line in block:
        if line.upper().startswith("HTTP/"):
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit():
                status = int(parts[1])
        elif ":" in line:
            name, _, value = line.partition(":")
            pairs.append((name, value))
    return status, Headers(pairs)


# ---------------------------------------------------------------- CSP 解析

def parse_csp(value: str) -> Dict[str, List[str]]:
    """把 CSP 拆成 {指令名: [来源...]}。重复的指令只认第一个（与浏览器一致）。"""
    directives: Dict[str, List[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:
            directives[name] = [t.lower() for t in tokens[1:]]
    return directives


def _uses_nonce_or_hash(sources: List[str]) -> bool:
    return any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
               for s in sources)


# ---------------------------------------------------------------- 各项检查

def check_hsts(h: Headers, is_https: bool) -> Finding:
    name, full = "Strict-Transport-Security", WEIGHTS["Strict-Transport-Security"]
    value = h.get(name)
    fix = f"{name}: max-age=31536000; includeSubDomains"
    if not is_https:
        return Finding(name, FAIL, 0, full,
                       "页面不是通过 HTTPS 访问的，HSTS 无从谈起（浏览器会忽略 HTTP 上的 HSTS）",
                       "先给站点配好 HTTPS，把 HTTP 301 跳转到 HTTPS，再加上 " + fix)
    if value is None:
        return Finding(name, FAIL, 0, full,
                       "缺失：用户第一次输入 http:// 或被降级攻击时，连接可能被中间人劫持",
                       "加上 " + fix)
    first = value.split(",")[0]
    m = re.search(r"max-age\s*=\s*\"?(\d+)", first, re.I)
    if not m:
        return Finding(name, FAIL, 0, full, "格式错误：没有有效的 max-age", "改成 " + fix, value)
    age = int(m.group(1))
    subdomains = "includesubdomains" in first.lower()
    preload = "preload" in first.lower()
    if age == 0:
        return Finding(name, FAIL, 0, full, "max-age=0，等于让浏览器删除 HSTS 记录", "改成 " + fix, value)
    if age < HSTS_MIN_AGE:
        return Finding(name, WARN, full // 2, full,
                       f"max-age={age}（约 {age // 86400} 天），太短，过期后又会退回可被降级的状态",
                       f"至少 {HSTS_MIN_AGE}（180 天），推荐 31536000（1 年）", value)
    if not subdomains:
        return Finding(name, WARN, full - 5, full,
                       f"max-age={age}，但没有 includeSubDomains，子域名仍可能被利用来设置 Cookie",
                       "确认所有子域名都支持 HTTPS 后，加上 includeSubDomains", value)
    msg = f"max-age={age}，包含子域名"
    if preload:
        msg += "，并声明了 preload"
        if age < HSTS_PRELOAD_AGE:
            msg += f"（但 preload 列表要求 max-age ≥ {HSTS_PRELOAD_AGE}）"
    return Finding(name, PASS, full, full, msg, "", value)


def check_csp(h: Headers) -> Finding:
    name, full = "Content-Security-Policy", WEIGHTS["Content-Security-Policy"]
    value = h.get(name)
    starter = ("从一个严格的起点开始再按需放开，例如："
               "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'。"
               "可以先用 Content-Security-Policy-Report-Only 观察一段时间，确认不影响页面再切换")
    if value is None:
        if "Content-Security-Policy-Report-Only" in h:
            return Finding(name, WARN, 5, full,
                           "只有 Report-Only 模式：浏览器只报告违规，不会拦截任何东西",
                           "观察没问题后，把同样的策略改用 Content-Security-Policy 头下发",
                           h.get("Content-Security-Policy-Report-Only"))
        return Finding(name, FAIL, 0, full,
                       "缺失：XSS 注入的脚本可以随意执行、随意加载外部资源",
                       starter)
    d = parse_csp(value)
    script = d.get("script-src", d.get("default-src"))
    problems, tips = [], []
    score = full
    if script is None:
        problems.append("没有 default-src 也没有 script-src，脚本来源不受限制")
        tips.append("加上 default-src 'self'（或明确的 script-src）")
        score -= 15
    else:
        strict_dynamic = "'strict-dynamic'" in script
        has_nonce = _uses_nonce_or_hash(script)
        # 有 nonce/hash 时，支持 CSP2 的浏览器会忽略 'unsafe-inline'，那只是给老浏览器的兼容写法
        if "'unsafe-inline'" in script and not has_nonce:
            problems.append("脚本允许 'unsafe-inline'，内联脚本 XSS 不会被拦截")
            tips.append("去掉 'unsafe-inline'，改用 nonce 或 hash 给需要的内联脚本放行")
            score -= 10
        if "'unsafe-eval'" in script:
            problems.append("脚本允许 'unsafe-eval'（eval/new Function 可用）")
            tips.append("重构掉 eval，去掉 'unsafe-eval'")
            score -= 5
        wide = [s for s in script if s in ("*", "http:", "https:", "data:")]
        if wide and not strict_dynamic:
            problems.append("脚本来源过宽：" + " ".join(wide))
            tips.append("把 *、http:、https:、data: 换成具体的域名，或使用 nonce + 'strict-dynamic'")
            score -= 5
    obj = d.get("object-src", d.get("default-src"))
    if obj is None or "*" in obj:
        problems.append("object-src 没有限制（Flash/插件类注入）")
        tips.append("加上 object-src 'none'")
        score -= 2
    if "base-uri" not in d:
        problems.append("没有 base-uri（攻击者可注入 <base> 改写相对路径）")
        tips.append("加上 base-uri 'self' 或 'none'")
        score -= 2
    score = max(score, 5)  # 有 CSP 总比没有强
    if not problems:
        return Finding(name, PASS, full, full, "策略存在且没有发现常见弱点", "", value)
    status = WARN if score >= full // 2 else FAIL
    return Finding(name, status, score, full, "；".join(problems), "；".join(tips), value)


def check_frame(h: Headers) -> Finding:
    name, full = "X-Frame-Options", WEIGHTS["X-Frame-Options"]
    csp = h.get("Content-Security-Policy")
    fa = parse_csp(csp).get("frame-ancestors") if csp else None
    if fa is not None:
        if "*" in fa:
            return Finding(name, FAIL, 0, full,
                           "CSP frame-ancestors 允许任何站点嵌入，点击劫持防护无效",
                           "改为 frame-ancestors 'self' 或 'none'", "frame-ancestors " + " ".join(fa))
        # CSP frame-ancestors 是 X-Frame-Options 的现代替代，优先级更高
        return Finding(name, PASS, full, full,
                       "由 CSP frame-ancestors 提供防点击劫持保护：" + " ".join(fa), "",
                       h.get(name))
    value = h.get(name)
    fix = "加上 X-Frame-Options: DENY（或 SAMEORIGIN），或在 CSP 里写 frame-ancestors 'self'"
    if value is None:
        return Finding(name, FAIL, 0, full,
                       "缺失：页面可被任意网站用 iframe 嵌入，存在点击劫持风险", fix)
    v = value.split(",")[0].strip().upper()
    if v in ("DENY", "SAMEORIGIN"):
        return Finding(name, PASS, full, full, v, "", value)
    if v.startswith("ALLOW-FROM"):
        return Finding(name, WARN, 5, full,
                       "ALLOW-FROM 已废弃，现代浏览器会忽略它（等于没设）",
                       "改用 CSP: frame-ancestors 'self' https://允许的域名", value)
    return Finding(name, FAIL, 0, full, f"无效的值：{value}", fix, value)


def check_nosniff(h: Headers) -> Finding:
    name, full = "X-Content-Type-Options", WEIGHTS["X-Content-Type-Options"]
    value = h.get(name)
    if value is not None and value.split(",")[0].strip().lower() == "nosniff":
        return Finding(name, PASS, full, full, "nosniff", "", value)
    msg = "缺失" if value is None else f"无效的值：{value}"
    return Finding(name, FAIL, 0, full,
                   msg + "：浏览器可能把上传的文本/图片“猜”成脚本执行（MIME 嗅探）",
                   "加上 X-Content-Type-Options: nosniff", value)


GOOD_REFERRER = {"no-referrer", "same-origin", "strict-origin",
                 "strict-origin-when-cross-origin"}
OK_REFERRER = {"origin", "origin-when-cross-origin", "no-referrer-when-downgrade"}


def check_referrer(h: Headers) -> Finding:
    name, full = "Referrer-Policy", WEIGHTS["Referrer-Policy"]
    value = h.get(name)
    fix = "加上 Referrer-Policy: strict-origin-when-cross-origin（或 no-referrer）"
    if value is None:
        return Finding(name, WARN, 5, full,
                       "缺失：现代浏览器默认 strict-origin-when-cross-origin，但老浏览器会把完整 URL 发给第三方",
                       fix)
    # 允许写多个值做回退，浏览器取最后一个它认识的
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    effective = tokens[-1] if tokens else ""
    if effective in GOOD_REFERRER:
        return Finding(name, PASS, full, full, effective, "", value)
    if effective == "unsafe-url":
        return Finding(name, FAIL, 0, full,
                       "unsafe-url：任何请求都会带上完整 URL（含路径和查询参数里的 token）",
                       fix, value)
    if effective in OK_REFERRER:
        return Finding(name, WARN, 5, full,
                       f"{effective}：跨站请求会泄露完整 URL 或来源", fix, value)
    return Finding(name, FAIL, 0, full, f"无效的值：{value}", fix, value)


def check_permissions(h: Headers) -> Finding:
    name, full = "Permissions-Policy", WEIGHTS["Permissions-Policy"]
    value = h.get(name)
    if value is not None and value.strip():
        return Finding(name, PASS, full, full, "已设置，限制了页面（和嵌入的 iframe）能用的浏览器功能", "", value)
    if "Feature-Policy" in h:
        return Finding(name, WARN, 5, full, "只有旧版 Feature-Policy",
                       "改用新语法 Permissions-Policy，例如 camera=(), microphone=(), geolocation=()",
                       h.get("Feature-Policy"))
    return Finding(name, WARN, 0, full,
                   "缺失：页面和第三方 iframe 可以申请摄像头、麦克风、定位等权限",
                   "加上 Permissions-Policy: camera=(), microphone=(), geolocation=()"
                   "，按实际需要放开")


def check_coop(h: Headers) -> Finding:
    name, full = "Cross-Origin-Opener-Policy", WEIGHTS["Cross-Origin-Opener-Policy"]
    value = h.get(name)
    if value is not None and value.strip().lower() in ("same-origin", "same-origin-allow-popups"):
        return Finding(name, PASS, full, full, value.strip(), "", value)
    msg = "缺失" if value is None else f"值为 {value}，没有隔离"
    return Finding(name, WARN, 0, full,
                   msg + "：被你打开或打开你的跨站窗口能拿到 window 引用（XS-Leaks、Tabnabbing）",
                   "加上 Cross-Origin-Opener-Policy: same-origin（需要和弹窗通信时用 same-origin-allow-popups）",
                   value)


# ---------------------------------------------------------------- 附加检查（只扣分）

LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
                "X-Generator"]


def check_info_leaks(h: Headers) -> List[Finding]:
    out = []
    for name in LEAK_HEADERS:
        value = h.get(name)
        if value is None:
            continue
        # Server: nginx 这种只有产品名的不算问题，带版本号才扣分
        if name == "Server" and not re.search(r"\d", value):
            continue
        out.append(Finding(name, WARN, -PENALTY_EACH, 0,
                           f"暴露了技术栈/版本号：{value}（方便攻击者对照已知漏洞）",
                           f"去掉或模糊化 {name}，例如 nginx 的 server_tokens off;"
                           "、PHP 的 expose_php = Off、Express 的 app.disable('x-powered-by')",
                           value))
    return out


def check_deprecated(h: Headers) -> List[Finding]:
    out = []
    xss = h.get("X-XSS-Protection")
    if xss is not None and xss.strip().split(";")[0].strip() != "0":
        out.append(Finding("X-XSS-Protection", INFO, 0, 0,
                           f"{xss}：XSS Auditor 已被所有主流浏览器移除，旧实现本身还能被滥用来泄露信息",
                           "设为 X-XSS-Protection: 0 或直接删掉，靠 CSP 防 XSS", xss))
    for name in ("Expect-CT", "Public-Key-Pins"):
        if name in h:
            out.append(Finding(name, INFO, 0, 0, "已废弃的响应头，浏览器不再处理",
                               f"可以删掉 {name}", h.get(name)))
    return out


def check_cookies(h: Headers, is_https: bool) -> List[Finding]:
    out = []
    for raw in h.get_all("Set-Cookie"):
        cookie_name = raw.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        names = {a.split("=", 1)[0].strip() for a in attrs}
        missing = []
        if is_https and "secure" not in names:
            missing.append("Secure")
        if "httponly" not in names:
            missing.append("HttpOnly")
        samesite = next((a.split("=", 1)[1].strip() for a in attrs
                         if a.startswith("samesite=")), None)
        if samesite is None:
            missing.append("SameSite")
        if samesite == "none" and "secure" not in names:
            missing.append("Secure（SameSite=None 必须带 Secure）")
        if not missing:
            continue
        out.append(Finding(f"Set-Cookie: {cookie_name}", WARN, -PENALTY_EACH, 0,
                           "缺少属性：" + ", ".join(missing),
                           "会话类 Cookie 推荐 Secure; HttpOnly; SameSite=Lax（或 Strict）。"
                           "如果前端 JS 确实要读这个 Cookie，可以不加 HttpOnly",
                           _mask_cookie(raw)))
    return out


def _mask_cookie(raw: str) -> str:
    """报告里不显示 Cookie 的值（可能是会话令牌），只留名字和属性。"""
    first, _, rest = raw.partition(";")
    name = first.split("=", 1)[0].strip()
    return f"{name}=…" + (";" + rest if rest else "")


def check_https_redirect(url: str, final_url: str) -> List[Finding]:
    if urlsplit(url).scheme == "http" and urlsplit(final_url).scheme != "https":
        return [Finding("HTTP→HTTPS 跳转", WARN, -PENALTY_EACH * 2, 0,
                        "用 http:// 访问时没有被跳转到 https://，流量是明文的",
                        "在服务器上把所有 HTTP 请求 301 到 HTTPS，并配合 HSTS")]
    return []


# ---------------------------------------------------------------- 汇总

def analyze(url: str, final_url: str, status: Optional[int], h: Headers) -> Report:
    is_https = urlsplit(final_url).scheme == "https"
    r = Report(url=url, final_url=final_url, status_code=status)
    r.findings += [
        check_hsts(h, is_https),
        check_csp(h),
        check_frame(h),
        check_nosniff(h),
        check_referrer(h),
        check_permissions(h),
        check_coop(h),
    ]
    r.findings += check_https_redirect(url, final_url)
    r.findings += check_cookies(h, is_https)
    r.findings += check_info_leaks(h)
    r.findings += check_deprecated(h)
    return r


def normalize_url(url: str) -> str:
    """没写协议时默认 https://。"""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"只支持 http/https 网址：{url}")
    return url


def fetch(url: str, timeout: float = 10.0) -> Tuple[str, int, Headers]:
    """发一个 GET 请求（自动跟随跳转），返回 (最终网址, 状态码, 响应头)。

    用 GET 而不是 HEAD：有些服务器对 HEAD 返回的头和 GET 不一样。只读响应头，不下载正文。
    4xx/5xx 也照常分析，错误页同样应该带安全头。
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp = e
    try:
        pairs = list(resp.headers.items())
        return resp.geturl(), resp.getcode(), Headers(pairs)
    finally:
        resp.close()


# ---------------------------------------------------------------- 输出

def print_report(r: Report, show_values: bool = False) -> None:
    print(f"\n🔎 {r.url}")
    if r.final_url != r.url:
        print(f"   → 跳转到 {r.final_url}")
    if r.status_code is not None:
        print(f"   HTTP 状态码 {r.status_code}")
    print(f"\n   得分 {r.score}/100   等级 {r.grade}\n")
    for f in r.findings:
        pts = f"{f.score}/{f.max_score}" if f.max_score else (f"{f.score}" if f.score else "")
        print(f" {ICONS[f.status]} {f.header:<28} {pts:>6}  {f.message}")
        if show_values and f.value:
            print(f"      当前值: {f.value}")
        if f.advice:
            print(f"      👉 {f.advice}")
    print()


def report_to_dict(r: Report) -> dict:
    return {"url": r.url, "final_url": r.final_url, "status_code": r.status_code,
            "score": r.score, "grade": r.grade,
            "findings": [asdict(f) for f in r.findings]}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="检查网站的 HTTP 安全响应头，给出评分和修复建议。")
    parser.add_argument("urls", nargs="*", help="要检查的网址，可以写多个（不写协议默认 https）")
    parser.add_argument("-f", "--file", metavar="PATH",
                        help="离线分析：读取 curl -sI 输出的响应头文件（- 表示标准输入）")
    parser.add_argument("--url", dest="file_url", default="https://example.invalid/",
                        help="配合 --file：这些响应头来自哪个网址（用来判断是否 HTTPS）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("-v", "--show-values", action="store_true", help="显示每个响应头的原始值")
    parser.add_argument("--fail-under", type=int, metavar="N",
                        help="任一网址得分低于 N 时退出码为 1（适合放进 CI）")
    parser.add_argument("--timeout", type=float, default=10.0, help="请求超时秒数（默认 10）")
    args = parser.parse_args(argv)

    if not args.urls and not args.file:
        parser.error("请给出至少一个网址，或用 --file 读取响应头文件")

    reports: List[Report] = []
    errors = 0
    if args.file:
        if args.file == "-":
            text = sys.stdin.read()
        else:
            with open(args.file, encoding="utf-8") as fh:
                text = fh.read()
        status, h = parse_raw_headers(text)
        reports.append(analyze(args.file_url, args.file_url, status, h))
    for raw in args.urls:
        try:
            url = normalize_url(raw)
            final_url, status, h = fetch(url, timeout=args.timeout)
        except (ValueError, urllib.error.URLError, OSError) as e:
            print(f"❌ {raw}: 请求失败：{getattr(e, 'reason', e)}", file=sys.stderr)
            errors += 1
            continue
        reports.append(analyze(url, final_url, status, h))

    if args.json:
        print(json.dumps([report_to_dict(r) for r in reports], ensure_ascii=False, indent=2))
    else:
        for r in reports:
            print_report(r, show_values=args.show_values)

    if errors and not reports:
        return 2
    if args.fail_under is not None and any(r.score < args.fail_under for r in reports):
        return 1
    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
