"""Authorized, non-intrusive checks and the assessment report."""

from __future__ import annotations

import json
import os
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

AUTH_PHRASE = "I am authorized to test this host"
PORTS = (22, 80, 443, 8080)
PORT_PAUSE_SECONDS = 0.5
TIMEOUT = 5
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)
REPORT_DIR = Path(__file__).resolve().parent / "reports"
COYOTE_URL = os.environ.get("COYOTE_BASE_URL", "https://coyotegpt.ngrok.app/api/v1").rstrip("/")
COYOTE_MODEL = os.environ.get("COYOTE_MODEL", "classroom-tutor-a")


@dataclass
class Finding:
    severity: str
    area: str
    title: str
    detail: str


@dataclass
class Assessment:
    operator: str
    engagement: str
    host: str
    notes: str
    generated_at: str
    modules: list[str]
    dns: list[dict] = field(default_factory=list)
    http: dict = field(default_factory=dict)
    tls: dict = field(default_factory=dict)
    ports: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coyote: dict = field(default_factory=dict)

    @property
    def review_count(self) -> int:
        return sum(1 for item in self.findings if item.severity in {"Review", "Fail"})

    @property
    def open_ports(self) -> int:
        return sum(1 for item in self.ports if item["state"] == "open")


def normalize_host(raw: str) -> str:
    text = (raw or "").strip()
    if not text or any(ch.isspace() for ch in text):
        raise ValueError("Enter one hostname or IP address.")
    if "://" in text:
        text = urlparse(text).hostname or ""
    text = text.strip("[]").rstrip(".")
    if not text or "/" in text or len(text) > 253:
        raise ValueError("Enter a hostname or IP, without a path.")
    return text


def assess(
    operator: str,
    engagement: str,
    confirmation: str,
    target: str,
    modules: list[str] | None,
    notes: str,
    on_step=None,
) -> Assessment:
    operator = (operator or "").strip()
    engagement = (engagement or "").strip()
    if not operator:
        raise ValueError("Enter your name. It is printed on the report.")
    if not engagement:
        raise ValueError("Enter an engagement name, such as the class lab title.")
    if (confirmation or "").strip() != AUTH_PHRASE:
        raise ValueError(f"Type the authorization phrase exactly: {AUTH_PHRASE}")
    host = normalize_host(target)
    selected = list(modules or [])
    if not selected:
        raise ValueError("Choose at least one check.")

    result = Assessment(
        operator=operator,
        engagement=engagement,
        host=host,
        notes=(notes or "").strip(),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        modules=selected,
    )
    if "DNS" in selected:
        _step(on_step, 0.2, "Looking up DNS")
        result.dns = _dns(host)
    if "HTTP headers" in selected:
        _step(on_step, 0.4, "Requesting the page")
        result.http = _http(host)
    if "TLS certificate" in selected:
        _step(on_step, 0.6, "Reading the certificate")
        result.tls = _tls(host)
    if "Common ports" in selected:
        _step(on_step, 0.75, "Checking common ports")
        result.ports = _ports(host)
    _step(on_step, 0.92, "Writing the report")
    result.findings = _findings(result)
    return result


def _step(on_step, fraction: float, desc: str) -> None:
    if on_step is not None:
        on_step(fraction, desc)


def _dns(host: str) -> list[dict]:
    rows = []
    for family, label in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
        try:
            infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
            addresses = sorted({item[4][0] for item in infos})
            rows.append({"record": label, "result": ", ".join(addresses) if addresses else "none"})
        except socket.gaierror as exc:
            rows.append({"record": label, "result": f"no record ({exc.strerror or exc})"})
    return rows


def _http(host: str) -> dict:
    last_error = "no response"
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        request = Request(url, headers={"User-Agent": "LabRecon/1.0"})
        try:
            with urlopen(request, timeout=TIMEOUT) as response:
                status = getattr(response, "status", None) or response.getcode()
                headers = {key.lower(): value for key, value in response.headers.items()}
                final_url = response.geturl()
            return _http_record(url, final_url, status, headers, "")
        except HTTPError as exc:
            headers = {key.lower(): value for key, value in exc.headers.items()} if exc.headers else {}
            return _http_record(url, url, exc.code, headers, "")
        except URLError as exc:
            last_error = f"{scheme} failed ({exc.reason})"
        except TimeoutError:
            last_error = f"{scheme} timed out"
    return {"ok": False, "error": last_error, "headers": [], "cookies": []}


def _http_record(url: str, final_url: str, status: int, headers: dict, error: str) -> dict:
    header_rows = []
    for name in SECURITY_HEADERS:
        value = headers.get(name, "")
        header_rows.append(
            {
                "header": name,
                "state": "present" if value else "missing",
                "value": value[:180],
            }
        )
    cookies = []
    for raw in _header_list(headers, "set-cookie"):
        lowered = raw.lower()
        cookies.append(
            {
                "cookie": raw.split("=", 1)[0][:40],
                "secure": "yes" if "secure" in lowered else "no",
                "httponly": "yes" if "httponly" in lowered else "no",
            }
        )
    return {
        "ok": True,
        "url": url,
        "final_url": final_url,
        "status": status,
        "server": headers.get("server", ""),
        "powered_by": headers.get("x-powered-by", ""),
        "error": error,
        "headers": header_rows,
        "cookies": cookies,
    }


def _header_list(headers: dict, name: str) -> list[str]:
    value = headers.get(name, "")
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _tls(host: str) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()
                protocol = secure.version() or ""
    except Exception as exc:
        return {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}
    not_after = cert.get("notAfter", "")
    remaining = _days_remaining(not_after)
    return {
        "ok": True,
        "subject": _cert_name(cert.get("subject")) or "unknown",
        "issuer": _cert_name(cert.get("issuer")) or "unknown",
        "expires": not_after or "unknown",
        "days_remaining": remaining,
        "protocol": protocol or "unknown",
        "error": "",
    }


def _cert_name(parts) -> str:
    if not parts:
        return ""
    return ", ".join(f"{key}={value}" for group in parts for key, value in group)


def _days_remaining(not_after: str) -> int | None:
    if not not_after:
        return None
    try:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (expires - datetime.now(timezone.utc)).days


def _ports(host: str) -> list[dict]:
    rows = []
    for index, port in enumerate(PORTS):
        if index:
            time.sleep(PORT_PAUSE_SECONDS)
        rows.append({"port": port, "service": _service_name(port), "state": _probe_port(host, port)})
    return rows


def _service_name(port: int) -> str:
    return {22: "ssh", 80: "http", 443: "https", 8080: "http-alt"}.get(port, "unknown")


def _probe_port(host: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return f"error ({exc.strerror or exc.__class__.__name__})"
    infos.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
    saw_closed = False
    last = "no address"
    for family, socktype, proto, _canon, sockaddr in infos:
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(TIMEOUT)
                sock.connect(sockaddr)
            return "open"
        except ConnectionRefusedError:
            saw_closed = True
        except TimeoutError:
            last = "filtered or timed out"
        except OSError as exc:
            if exc.errno in {101, 113}:
                last = "filtered or unreachable"
            else:
                last = f"error ({exc.strerror or exc.__class__.__name__})"
    return "closed" if saw_closed else last


def _findings(result: Assessment) -> list[Finding]:
    findings: list[Finding] = []
    headers = result.http.get("headers") or []
    missing = [row["header"] for row in headers if row["state"] == "missing"]
    if missing:
        findings.append(
            Finding(
                "Review",
                "HTTP",
                "Security headers are missing",
                "These response headers are absent: " + ", ".join(missing) + ".",
            )
        )
    if result.http.get("server") or result.http.get("powered_by"):
        disclosed = ", ".join(
            part for part in (result.http.get("server"), result.http.get("powered_by")) if part
        )
        findings.append(
            Finding(
                "Info",
                "HTTP",
                "The server names its software",
                f"Response identified: {disclosed}.",
            )
        )
    weak_cookies = [
        row["cookie"]
        for row in result.http.get("cookies") or []
        if row["secure"] == "no" or row["httponly"] == "no"
    ]
    if weak_cookies:
        findings.append(
            Finding(
                "Review",
                "HTTP",
                "A cookie is missing Secure or HttpOnly",
                "Cookies to review: " + ", ".join(weak_cookies) + ".",
            )
        )
    if result.tls.get("ok"):
        days = result.tls.get("days_remaining")
        if days is None:
            severity, title = "Info", "Certificate expiration could not be parsed"
        elif days < 0:
            severity, title = "Fail", "The TLS certificate is expired"
        elif days < 30:
            severity, title = "Review", "The TLS certificate expires soon"
        else:
            severity, title = "Info", "The TLS certificate is current"
        findings.append(
            Finding(severity, "TLS", title, f"{result.tls.get('expires')} ({days} days).")
        )
    elif result.tls:
        findings.append(
            Finding("Review", "TLS", "No TLS certificate was collected", result.tls.get("error", ""))
        )
    for row in result.ports:
        if row["state"] == "open" and row["port"] == 22:
            findings.append(
                Finding("Review", "Ports", "SSH is reachable", "Port 22 accepted a connection.")
            )
    if result.http.get("ok") and str(result.http.get("url", "")).startswith("http://"):
        findings.append(
            Finding("Review", "HTTP", "The site responded only over HTTP", result.http.get("url", ""))
        )
    return findings


def recommendations(result: Assessment) -> list[str]:
    """Defensive follow-ups an operator can put in the lab write-up."""
    steps: list[str] = []
    for item in result.findings:
        if item.severity not in {"Review", "Fail"}:
            continue
        if item.title == "Security headers are missing":
            steps.append("Add the missing response headers on the web server, then run the HTTP check again.")
        elif item.title == "A cookie is missing Secure or HttpOnly":
            steps.append("Set Secure and HttpOnly on session cookies before the next worksheet run.")
        elif item.title == "The TLS certificate is expired":
            steps.append("Replace the expired certificate before relying on this host.")
        elif item.title == "The TLS certificate expires soon":
            steps.append("Renew the certificate before it expires, then record the new date.")
        elif item.title == "No TLS certificate was collected":
            steps.append("Confirm the host is supposed to offer HTTPS on port 443, then rerun the certificate check.")
        elif item.title == "SSH is reachable":
            steps.append("Confirm SSH is meant to be reachable, and that login uses keys.")
        elif item.title == "The site responded only over HTTP":
            steps.append("Serve the site over HTTPS and redirect plain HTTP to it.")
    if not steps:
        steps.append("No follow-up is required for the selected checks. Attach this report to the lab notes.")
    return steps


def to_markdown(result: Assessment) -> str:
    lines = [
        f"# {result.engagement}",
        "",
        "## Engagement",
        "",
        f"- Operator: {result.operator}",
        f"- Target: {result.host}",
        f"- Generated: {result.generated_at}",
        f"- Checks: {', '.join(result.modules)}",
        "",
        result.notes or "No operator notes.",
        "",
        "## Summary",
        "",
        f"- Items to review: {result.review_count}",
        f"- Open ports: {result.open_ports} of {len(result.ports) or 0} checked",
        "",
        "## Findings",
        "",
    ]
    if not result.findings:
        lines.append("No findings were produced for the selected checks.")
    for item in result.findings:
        lines.append(f"### {item.severity} — {item.title}")
        lines.append("")
        lines.append(f"{item.area}. {item.detail}")
        lines.append("")
    lines.extend(["## Next steps", ""])
    for index, step in enumerate(recommendations(result), start=1):
        lines.append(f"{index}. {step}")
    lines.append("")
    lines.extend(["## Evidence", ""])
    if result.dns:
        lines.append("### DNS")
        lines.append("")
        for row in result.dns:
            lines.append(f"- {row['record']}: {row['result']}")
        lines.append("")
    if result.http:
        lines.append("### HTTP")
        lines.append("")
        if result.http.get("ok"):
            lines.append(f"- URL: {result.http.get('url')}")
            lines.append(f"- Final URL: {result.http.get('final_url')}")
            lines.append(f"- Status: {result.http.get('status')}")
            for row in result.http.get("headers") or []:
                lines.append(f"- {row['header']}: {row['state']} {row['value']}".rstrip())
        else:
            lines.append(f"- {result.http.get('error')}")
        cookies = result.http.get("cookies") or []
        if cookies:
            lines.append("- Cookies:")
            for row in cookies:
                lines.append(
                    f"  - {row['cookie']}: Secure {row['secure']}, HttpOnly {row['httponly']}"
                )
        lines.append("")
    if result.tls:
        lines.append("### TLS")
        lines.append("")
        if result.tls.get("ok"):
            lines.append(f"- Subject: {result.tls.get('subject')}")
            lines.append(f"- Issuer: {result.tls.get('issuer')}")
            lines.append(f"- Protocol: {result.tls.get('protocol')}")
            lines.append(f"- Expires: {result.tls.get('expires')}")
            lines.append(f"- Days remaining: {result.tls.get('days_remaining')}")
        else:
            lines.append(f"- {result.tls.get('error')}")
        lines.append("")
    if result.ports:
        lines.append("### Ports")
        lines.append("")
        for row in result.ports:
            lines.append(f"- {row['port']}/{row['service']}: {row['state']}")
        lines.append("")
    note = result.coyote or {}
    if note.get("text") or note.get("error"):
        lines.extend(["## CoyoteGPT", ""])
        if note.get("model"):
            lines.append(f"Model: {note['model']}")
            lines.append("")
        lines.append(note.get("text") or note.get("error"))
        lines.append("")
    lines.extend(
        [
            "## Method",
            "",
            "Lab Recon makes ordinary DNS lookups, one HTTP request, one TLS handshake, and a connect check to ports 22, 80, 443, and 8080. It waits half a second between port checks. When CoyoteGPT is selected, that local class model reads these findings and writes the note in this report. It does not guess passwords, exploit services, or scan the full port range.",
            "",
            "Use this report only for hosts the operator is authorized to test.",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(result: Assessment) -> tuple[str, str]:
    REPORT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_host = "".join(ch if ch.isalnum() else "-" for ch in result.host)[:40].strip("-")
    stem = f"{safe_host or 'host'}-{stamp}"
    markdown_path = REPORT_DIR / f"{stem}.md"
    json_path = REPORT_DIR / f"{stem}.json"
    markdown_path.write_text(to_markdown(result), encoding="utf-8")
    payload = asdict(result)
    payload["findings"] = [asdict(item) for item in result.findings]
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(markdown_path), str(json_path)


def _coyote_key() -> str:
    """Read the key from the environment only. Never from a file in this project."""
    placeholders = {"", "ollama", "changeme"}
    for name in ("COYOTE_API_KEY", "OPENAI_API_KEY"):
        value = os.environ.get(name, "").strip().strip('"').strip("'")
        if value and value not in placeholders and not value.startswith("${"):
            return value
    return ""


def explain_findings(result: Assessment) -> dict:
    """Ask the class CoyoteGPT model to explain findings already collected."""
    model = COYOTE_MODEL
    key = _coyote_key()
    if not key:
        return {
            "ok": False,
            "model": model,
            "text": "",
            "error": "CoyoteGPT did not run. Set COYOTE_API_KEY, then run the assessment again.",
        }
    packet = {
        "host": result.host,
        "engagement": result.engagement,
        "findings": [
            {
                "severity": item.severity,
                "area": item.area,
                "title": item.title,
                "detail": item.detail,
            }
            for item in result.findings
        ],
        "next_steps": recommendations(result),
    }
    payload = {
        "model": model,
        "temperature": 0.2,
        "max_tokens": 450,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You write a short note for an authorized lab report. "
                    "Use only the findings in the user message. Explain what each review item means. "
                    "Suggest defensive follow-up only, such as response headers, certificates, and confirming a service should be reachable. "
                    "Do not invent results. Do not give exploit steps, payloads, credentials, or scan commands. "
                    "Stay under 180 words."
                ),
            },
            {"role": "user", "content": json.dumps(packet)},
        ],
    }
    request = Request(
        f"{COYOTE_URL}/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=45) as response:
            body = json.load(response)
        text = body["choices"][0]["message"]["content"].strip()
        used = body.get("model") or model
        return {"ok": True, "model": used, "text": text, "error": ""}
    except (URLError, TimeoutError, KeyError, json.JSONDecodeError, OSError) as exc:
        return {
            "ok": False,
            "model": model,
            "text": "",
            "error": f"CoyoteGPT did not answer ({exc.__class__.__name__}). The checks are still in this report.",
        }
