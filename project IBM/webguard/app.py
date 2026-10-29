import streamlit as st
import urllib.request
import urllib.error
import ssl
import json
import time

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WebGuard — Web Security Scanner",
    page_icon="🔍",
    layout="wide",
)

# ── Custom CSS — dark theme ───────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0d1117; color: #e6edf3; }

    div[data-testid="metric-container"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 20px 24px;
    }
    div[data-testid="metric-container"] label {
        color: #8b949e !important;
        font-size: 13px !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: .05em;
    }
    div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
        color: #58a6ff !important;
        font-size: 2.2rem !important;
        font-weight: 700 !important;
    }

    /* Input box */
    .stTextInput input {
        background-color: #161b22 !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
        border-radius: 8px !important;
    }

    /* Buttons */
    .stButton > button {
        background-color: #238636 !important;
        color: #ffffff !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        padding: 10px 28px !important;
    }
    .stButton > button:hover {
        background-color: #2ea043 !important;
    }

    hr { border-color: #30363d; }

    .pass-box {
        background:#122d22; border:1px solid #3fb950; border-radius:8px;
        padding:12px 16px; margin-bottom:8px;
    }
    .fail-box {
        background:#2d1b1b; border:1px solid #f85149; border-radius:8px;
        padding:12px 16px; margin-bottom:8px;
    }
    .warn-box {
        background:#2b2106; border:1px solid #d29922; border-radius:8px;
        padding:12px 16px; margin-bottom:8px;
    }
    .info-box {
        background:#0d2044; border:1px solid #58a6ff; border-radius:8px;
        padding:12px 16px; margin-bottom:8px;
    }
</style>
""", unsafe_allow_html=True)

# ── Security headers to check ─────────────────────────────────────────────────
# Each entry: (Header name, Why it matters, Risk if missing)
SECURITY_HEADERS = [
    (
        "Strict-Transport-Security",
        "Forces browsers to use HTTPS only — prevents downgrade attacks.",
        "HIGH — attacker can intercept traffic over plain HTTP.",
    ),
    (
        "Content-Security-Policy",
        "Controls which scripts/resources the browser is allowed to load.",
        "HIGH — site is vulnerable to Cross-Site Scripting (XSS) attacks.",
    ),
    (
        "X-Frame-Options",
        "Prevents the page from being embedded in an iframe on another site.",
        "MEDIUM — site may be vulnerable to Clickjacking attacks.",
    ),
    (
        "X-Content-Type-Options",
        "Stops browsers from guessing the file type (MIME sniffing).",
        "MEDIUM — browser may execute malicious files as scripts.",
    ),
    (
        "Referrer-Policy",
        "Controls how much referrer information is sent with requests.",
        "LOW — sensitive URL data may leak to third-party sites.",
    ),
    (
        "Permissions-Policy",
        "Restricts access to browser features like camera, microphone, location.",
        "LOW — malicious scripts could access sensitive device features.",
    ),
    (
        "X-XSS-Protection",
        "Enables the browser's built-in XSS filter (older browsers).",
        "LOW — older browsers get no XSS protection.",
    ),
]

# ── CORS check ────────────────────────────────────────────────────────────────
def check_cors(headers):
    """
    CORS (Cross-Origin Resource Sharing) check.
    If Access-Control-Allow-Origin is set to '*', any website can read
    responses from this server — a common misconfiguration.
    """
    acao = headers.get("access-control-allow-origin", "")
    if acao == "*":
        return "FAIL", "Access-Control-Allow-Origin: * — any origin allowed (open CORS)"
    elif acao:
        return "PASS", f"Access-Control-Allow-Origin: {acao}"
    else:
        return "INFO", "Access-Control-Allow-Origin header not present"

# ── HTTPS redirect check ──────────────────────────────────────────────────────
def check_https_redirect(url):
    """
    Checks if the HTTP version of the site redirects to HTTPS.
    A site that doesn't redirect leaves users on an unencrypted connection.
    """
    if url.startswith("https://"):
        http_url = url.replace("https://", "http://", 1)
    else:
        return "INFO", "Scan was run on HTTP — try with https://"

    try:
        # We don't follow redirects so we can see the redirect response directly
        req = urllib.request.Request(http_url, method="HEAD")
        ctx = ssl.create_default_context()
        # We want to see the raw redirect, not follow it
        opener = urllib.request.build_opener(
            urllib.request.HTTPRedirectHandler()
        )
        resp = opener.open(req, timeout=5)
        final_url = resp.geturl()
        if final_url.startswith("https://"):
            return "PASS", f"HTTP correctly redirects to HTTPS ({final_url})"
        else:
            return "FAIL", "HTTP does NOT redirect to HTTPS — traffic can be intercepted"
    except Exception:
        return "PASS", "HTTP version unreachable — HTTPS-only site (good)"

# ── Cookie security check ─────────────────────────────────────────────────────
def check_cookies(headers):
    """
    Checks Set-Cookie headers for Secure and HttpOnly flags.
    - Secure: cookie only sent over HTTPS
    - HttpOnly: JavaScript cannot read the cookie (prevents XSS cookie theft)
    """
    set_cookie = headers.get("set-cookie", "")
    if not set_cookie:
        return "INFO", "No Set-Cookie header found (no cookies set on this response)"

    issues = []
    if "secure" not in set_cookie.lower():
        issues.append("missing Secure flag")
    if "httponly" not in set_cookie.lower():
        issues.append("missing HttpOnly flag")

    if issues:
        return "FAIL", f"Cookie issues: {', '.join(issues)} — cookies may be stolen"
    return "PASS", "Cookies have Secure and HttpOnly flags set"

# ── Server info leak check ────────────────────────────────────────────────────
def check_server_info(headers):
    """
    Checks if the Server header reveals software name/version.
    Example: 'Server: Apache/2.4.51' tells attackers exactly what to exploit.
    """
    server = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")

    leaks = []
    if server:
        leaks.append(f"Server: {server}")
    if x_powered:
        leaks.append(f"X-Powered-By: {x_powered}")

    if leaks:
        return "WARN", "Server info exposed: " + " | ".join(leaks)
    return "PASS", "No server version information leaked"

# ── Score calculator ──────────────────────────────────────────────────────────
def calculate_score(results):
    """
    Converts check results into a 0–100 security score.
    PASS = full points, WARN = half points, FAIL/INFO = 0 points.
    """
    total_checks = len(results)
    if total_checks == 0:
        return 0
    points = sum(
        2 if r["status"] == "PASS" else
        1 if r["status"] == "WARN" else
        0
        for r in results
    )
    max_points = total_checks * 2
    return round((points / max_points) * 100)

def score_label(score):
    if score >= 80:
        return "🟢 Good", "#3fb950"
    elif score >= 50:
        return "🟡 Fair", "#d29922"
    else:
        return "🔴 Poor", "#f85149"

# ── Main scanner function ─────────────────────────────────────────────────────
def scan_url(url):
    """
    Fetches the URL and runs all security checks against the response headers.
    Returns a list of result dicts and the raw headers dict.
    """
    # Make sure the URL starts with http:// or https://
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "WebGuard-Scanner/1.0 (Educational)"},
    )

    resp = urllib.request.urlopen(req, context=ctx, timeout=10)
    # Convert all header names to lowercase for consistent lookup
    raw_headers = {k.lower(): v for k, v in resp.headers.items()}
    resp.close()

    results = []

    # ── Check each security header ────────────────────────────────────────────
    for header_name, description, risk in SECURITY_HEADERS:
        value = raw_headers.get(header_name.lower(), "")
        if value:
            results.append({
                "check":       header_name,
                "status":      "PASS",
                "detail":      f"Present: {value[:80]}",   # trim long values
                "description": description,
                "risk":        "—",
            })
        else:
            results.append({
                "check":       header_name,
                "status":      "FAIL",
                "detail":      "Header is MISSING from the response",
                "description": description,
                "risk":        risk,
            })

    # ── Extra checks ──────────────────────────────────────────────────────────
    cors_status, cors_detail = check_cors(raw_headers)
    results.append({
        "check":       "CORS (Access-Control-Allow-Origin)",
        "status":      cors_status,
        "detail":      cors_detail,
        "description": "Controls which external sites can read API responses.",
        "risk":        "HIGH — any website can steal data from your API." if cors_status == "FAIL" else "—",
    })

    https_status, https_detail = check_https_redirect(url)
    results.append({
        "check":       "HTTPS Redirect",
        "status":      https_status,
        "detail":      https_detail,
        "description": "HTTP traffic should always redirect to HTTPS.",
        "risk":        "HIGH — users on HTTP have unencrypted connections." if https_status == "FAIL" else "—",
    })

    cookie_status, cookie_detail = check_cookies(raw_headers)
    results.append({
        "check":       "Cookie Security Flags",
        "status":      cookie_status,
        "detail":      cookie_detail,
        "description": "Cookies must use Secure and HttpOnly flags.",
        "risk":        "MEDIUM — cookies can be stolen via XSS or HTTP." if cookie_status == "FAIL" else "—",
    })

    server_status, server_detail = check_server_info(raw_headers)
    results.append({
        "check":       "Server Info Leak",
        "status":      server_status,
        "detail":      server_detail,
        "description": "Server/version headers help attackers pick the right exploit.",
        "risk":        "LOW — attacker knows what software to target." if server_status == "WARN" else "—",
    })

    return results, raw_headers, url

# ═══════════════════════════════════════════════════════════════════════════════
# UI
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("# 🔍 WebGuard")
st.markdown(
    '<p style="color:#8b949e;font-size:16px;margin-bottom:4px;">'
    "Automated Web Security Header Scanner — checks sites for missing security "
    "headers, CORS misconfigurations, cookie flaws, and server info leaks."
    "</p>",
    unsafe_allow_html=True,
)
st.divider()

# ── URL input ─────────────────────────────────────────────────────────────────
url_input = st.text_input(
    "🌐 Enter a website URL to scan",
    placeholder="e.g. https://example.com",
    help="Include https:// for best results. Only scan sites you own or have permission to test.",
)

col_btn, col_note = st.columns([1, 4])
with col_btn:
    scan_clicked = st.button("🔍  Run Security Scan")
with col_note:
    st.markdown(
        '<p style="color:#8b949e;font-size:13px;margin-top:10px;">'
        "⚠️ Only scan websites you own or have permission to test. For educational use only."
        "</p>",
        unsafe_allow_html=True,
    )

# ── Run the scan ──────────────────────────────────────────────────────────────
if scan_clicked:
    if not url_input.strip():
        st.error("Please enter a URL first.")
    else:
        with st.spinner("Scanning... please wait"):
            time.sleep(0.5)   # small pause so spinner is visible
            try:
                results, raw_headers, scanned_url = scan_url(url_input.strip())

                # ── Summary metrics ───────────────────────────────────────────
                passed   = sum(1 for r in results if r["status"] == "PASS")
                failed   = sum(1 for r in results if r["status"] == "FAIL")
                warnings = sum(1 for r in results if r["status"] == "WARN")
                info     = sum(1 for r in results if r["status"] == "INFO")
                score    = calculate_score(results)
                label, label_color = score_label(score)

                st.divider()
                st.markdown(f"### 📊 Scan Results for `{scanned_url}`")

                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("🛡️ Security Score", f"{score}/100")
                m2.metric("✅ Passed",          passed)
                m3.metric("❌ Failed",          failed)
                m4.metric("⚠️ Warnings",        warnings)
                m5.metric("ℹ️ Info",            info)

                # Score bar
                bar_color = label_color
                st.markdown(
                    f"""
                    <div style="margin:16px 0 4px 0;font-size:14px;color:#8b949e;">
                        Overall Rating: <b style="color:{bar_color}">{label}</b>
                    </div>
                    <div style="background:#161b22;border-radius:8px;height:18px;width:100%;border:1px solid #30363d;">
                        <div style="background:{bar_color};width:{score}%;height:100%;border-radius:8px;"></div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # ── Detailed check results ────────────────────────────────────
                st.divider()
                st.markdown("### 🔎 Detailed Check Results")

                STATUS_STYLE = {
                    "PASS": ("pass-box", "✅ PASS", "#3fb950"),
                    "FAIL": ("fail-box", "❌ FAIL", "#f85149"),
                    "WARN": ("warn-box", "⚠️ WARN", "#d29922"),
                    "INFO": ("info-box", "ℹ️ INFO", "#58a6ff"),
                }

                for r in results:
                    box_class, badge, color = STATUS_STYLE[r["status"]]
                    risk_html = (
                        f"<br><span style='color:#f85149;font-size:12px;'>"
                        f"🔥 Risk: {r['risk']}</span>"
                        if r["risk"] != "—" else ""
                    )
                    st.markdown(
                        f"""
                        <div class="{box_class}">
                            <span style="color:{color};font-weight:700;">{badge}</span>
                            <span style="color:#e6edf3;font-weight:600;margin-left:10px;">{r['check']}</span>
                            <br>
                            <span style="color:#8b949e;font-size:13px;">{r['description']}</span>
                            <br>
                            <span style="color:#e6edf3;font-size:13px;">→ {r['detail']}</span>
                            {risk_html}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                # ── Raw headers dump ──────────────────────────────────────────
                with st.expander("🗂️ View Raw Response Headers"):
                    for k, v in raw_headers.items():
                        st.markdown(
                            f"<code style='color:#58a6ff'>{k}</code>"
                            f"<span style='color:#8b949e'> : </span>"
                            f"<span style='color:#e6edf3'>{v}</span>",
                            unsafe_allow_html=True,
                        )

                # ── Recommendations ───────────────────────────────────────────
                failed_checks = [r for r in results if r["status"] == "FAIL"]
                if failed_checks:
                    st.divider()
                    st.markdown("### 💡 Recommendations")
                    st.markdown(
                        '<p style="color:#8b949e;font-size:14px;">'
                        "Fix these missing headers by adding them to your web server config:</p>",
                        unsafe_allow_html=True,
                    )
                    for r in failed_checks:
                        st.markdown(
                            f"""
                            <div style="background:#161b22;border-left:3px solid #f85149;
                                        padding:10px 16px;margin-bottom:8px;border-radius:0 8px 8px 0;">
                                <b style="color:#f85149;">{r['check']}</b><br>
                                <span style="color:#8b949e;font-size:13px;">{r['risk']}</span>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

            except urllib.error.URLError as e:
                st.error(f"❌ Could not reach the URL: {e.reason} — check the address and try again.")
            except Exception as e:
                st.error(f"❌ Scan failed: {str(e)}")

# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
st.markdown(
    '<p style="color:#8b949e;font-size:13px;text-align:center;">'
    "WebGuard v1.0 · Built with Python &amp; Streamlit · For educational purposes only"
    "</p>",
    unsafe_allow_html=True,
)
