from flask import Flask, render_template, request, jsonify
from datetime import datetime, timezone
from urllib.parse import urlparse
import ipaddress
import socket
import requests

app = Flask(__name__)

# Stores successful scans during the current server session
scan_history = []

HEADERS_TO_CHECK = {
    "Content-Security-Policy":
        ("Medium", "Helps restrict unsafe content and scripts."),
    "Strict-Transport-Security":
        ("Medium", "Helps enforce HTTPS in supported browsers."),
    "X-Content-Type-Options":
        ("Low", "Helps prevent MIME-type sniffing."),
    "X-Frame-Options":
        ("Low", "Helps reduce clickjacking risks."),
    "Referrer-Policy":
        ("Low", "Controls referrer information sent by browsers."),
    "Permissions-Policy":
        ("Low", "Controls access to selected browser features.")
}


def validate_target(url):
    parsed = urlparse(url)

    if parsed.scheme != "https" or not parsed.hostname:
        return None, "Enter a valid HTTPS URL."

    if parsed.username or parsed.password:
        return None, "URLs containing credentials are not allowed."

    hostname = parsed.hostname

    try:
        addresses = socket.getaddrinfo(
            hostname, 443, type=socket.SOCK_STREAM
        )

        for result in addresses:
            address = ipaddress.ip_address(result[4][0])

            if not address.is_global:
                return None, "Private or non-public targets are blocked."

    except (socket.gaierror, ValueError):
        return None, "Could not resolve the target hostname."

    return parsed, None


def scan_headers(headers):
    findings = []

    for header, details in HEADERS_TO_CHECK.items():
        if header not in headers:
            findings.append({
                "title": f"Missing {header}",
                "severity": details[0],
                "category": "A02:2025 Security Misconfiguration",
                "evidence": f"The response does not include {header}.",
                "recommendation": details[1],
                "status": "Potential issue"
            })

    return findings


def scan_cookies(response):
    findings = []
    cookies = response.headers.get("Set-Cookie", "")

    if cookies:
        if "secure" not in cookies.lower():
            findings.append({
                "title": "Cookie Secure flag may be missing",
                "severity": "Medium",
                "category": "A02:2025 Security Misconfiguration",
                "evidence": "A Set-Cookie response may lack Secure.",
                "recommendation":
                    "Review each cookie and set Secure when appropriate.",
                "status": "Needs review"
            })

        if "httponly" not in cookies.lower():
            findings.append({
                "title": "Cookie HttpOnly flag may be missing",
                "severity": "Medium",
                "category": "A02:2025 Security Misconfiguration",
                "evidence": "A Set-Cookie response may lack HttpOnly.",
                "recommendation":
                    "Set HttpOnly on cookies that do not require JavaScript.",
                "status": "Needs review"
            })

    return findings


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/history", methods=["GET"])
def history():
    return jsonify(scan_history)


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    parsed, error = validate_target(url)

    if error:
        return jsonify({"error": error}), 400

    try:
        response = requests.get(
            parsed.geturl(),
            timeout=8,
            allow_redirects=False,
            stream=True,
            headers={
                "User-Agent": "WebShield-Authorized-Scanner/1.0"
            }
        )

        try:
            if 300 <= response.status_code < 400:
                return jsonify({
                    "error": "Redirect detected. Verify the destination "
                             "and submit its HTTPS URL separately."
                }), 400

            findings = scan_headers(response.headers)
            findings.extend(scan_cookies(response))

            # Create the scan result
            scan_result = {
                "target": parsed.hostname,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "status_code": response.status_code,
                "findings": findings,
                "summary": {
                    "total": len(findings),
                    "high": sum(
                        f["severity"] == "High"
                        for f in findings
                    ),
                    "medium": sum(
                        f["severity"] == "Medium"
                        for f in findings
                    ),
                    "low": sum(
                        f["severity"] == "Low"
                        for f in findings
                    )
                },
                "note": "These are preliminary configuration checks, "
                        "not proof of exploitable vulnerabilities."
            }

            # Save the scan in history
            scan_history.append(scan_result)

            # Return the result to the frontend
            return jsonify(scan_result)

        finally:
            response.close()

    except requests.RequestException as exc:
        app.logger.warning(
            "WebShield request failed: %s",
            exc
        )

        return jsonify({
            "error": "Unable to reach the target. "
                     "Check connectivity or try again."
        }), 502


if __name__ == "__main__":
    app.run(
        debug=False,
        host="127.0.0.1",
        port=5000
    )