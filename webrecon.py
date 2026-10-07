import socket
import requests
import ssl
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

def resolve_hostname(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        print("IP Address:", ip_address)
        return ip_address
    except socket.gaierror:
        print("[!] Could not resolve hostname.")
        sys.exit(1)

def get_http_response(target):
    try:
        response = requests.get(target, timeout=5)

        print("HTTP Status Code:", response.status_code)

        print("\nHTTPS / Redirect Analysis:")

        if response.url != target:
            print("[+] Redirect detected")
            print("    Final URL:", response.url)
        else:
            print("[+] No redirect detected")

        return response

    except requests.RequestException as error:
        print("[!] Could not connect to target:", error)
        sys.exit(1)

print("WebRecon")
print("Automated Web Reconnaissance Tool")
print("Starting...")

target = input("Enter target URL: ")

if not target.startswith(("http://", "https://")):
    target = "https://" + target

parsed_url = urlparse(target)
hostname = parsed_url.hostname
base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

tls_version = "Not available"
robots_found = False
sitemap_found = False
robots_content = ""

ip_address = resolve_hostname(hostname)

response = get_http_response(target)

print("\nTLS Information:")

final_url = urlparse(response.url)

if final_url.scheme == "https":
    try:
        context = ssl.create_default_context()

        with socket.create_connection((final_url.hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=final_url.hostname) as secure_sock:
                tls_version = secure_sock.version()
                print("[+] TLS Version:", tls_version)

    except (socket.error, ssl.SSLError):
        print("[!] Could not retrieve TLS information")
else:
    print("[!] Target is not using HTTPS")

print("\nHTTP Headers:")
for header, value in response.headers.items():
    print(f"{header}: {value}")

print("\nServer Information:")

server = response.headers.get("Server")

if server:
    print("[+] Server:", server)
else:
    print("[!] Server information not disclosed")

print("\nTechnology Information:")

powered_by = response.headers.get("X-Powered-By")

if powered_by:
    print("[+] X-Powered-By:", powered_by)
else:
    print("[!] X-Powered-By not disclosed")

print("\nRobots.txt:")

robots_url = base_url + "/robots.txt"

try:
    robots_response = requests.get(robots_url, timeout=5)

    if robots_response.status_code == 200:
        robots_found = True
        robots_content = robots_response.text
        
        print("[+] robots.txt found")
        print(robots_content)
    else:
            print("[!] robots.txt not found")

except requests.RequestException:
        print("[!] Could not access robots.txt")

print("\nSitemap:")

sitemap_url = base_url + "/sitemap.xml"

try:
    sitemap_response = requests.get(sitemap_url, timeout=5)

    if sitemap_response.status_code == 200:
        sitemap_found = True
        print("[+] sitemap.xml found")

        try:
            root = ET.fromstring(sitemap_response.text)

            print("\nDiscovered URLs:")

            discovered_urls = []

            namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

            for url in root.findall("sm:url", namespace):
                location = url.find("sm:loc", namespace)

                if location is not None:
                    print(" ", location.text)
                    discovered_urls.append(location.text)

        except ET.ParseError:
            print("[!] sitemap.xml contains invalid XML")

    else:
        print("[!] sitemap.xml not found")

except requests.RequestException:
    print("[!] Could not access sitemap.xml")

print("\nDirectory Discovery:")

directory_results = []

common_paths = [
    "/admin",
    "/login",
    "/dashboard",
    "/backup",
    "/uploads",
    "/api",
    "/test",
    "/dev",
    "/config"
]

for path in common_paths:
    url = base_url + path

    try:
        directory_response = requests.get(url, timeout=5)

        if directory_response.status_code == 200:
            print(f"[+] {path} -> 200 (Accessible)")
            directory_results.append(f"[+] {path} -> 200 (Accessible)")

        elif directory_response.status_code == 403:
            print(f"[!] {path} -> 403 (Access Denied)")
            directory_results.append(f"[!] {path} -> 403 (Access Denied)")

        elif directory_response.status_code in (301, 302):
            print(f"[+] {path} -> {directory_response.status_code} (Redirect)")
            directory_results.append(
            f"[+] {path} -> {directory_response.status_code} (Redirect)"
            )

    except requests.RequestException as error:
        print(f"[ERROR] Could not access {path}: {error}")

print("\nCookie Security Analysis:")

cookies = response.cookies

if cookies:
    for cookie in cookies:
        print(f"Cookie: {cookie.name}")

        if not cookie.secure:
            print("  [!] Secure flag missing")

        if "HttpOnly" not in cookie._rest:
            print("  [!] HttpOnly flag missing")

        if "SameSite" not in cookie._rest:
            print("  [!] SameSite attribute missing")
else:
    print("[+] No cookies set by target")

print("\nSecurity Header Analysis:")

findings = []

security_headers = [
"Strict-Transport-Security",
"Content-Security-Policy",
"X-Frame-Options",
"X-Content-Type-Options"
]

if 200 <= response.status_code < 300:
    for header in security_headers:
        if header in response.headers:
            print(f"[+] {header}: Present")
        else:
            print(f"[!] {header}: Missing")
            findings.append(header)
else:
    print("[!] Skipped: HTTP response is not a successful 2xx response.")

print("\n========== WEBRECON SUMMARY ==========")

print("Target:", target)
print("IP Address:", ip_address)
print("HTTP Status:", response.status_code)
print("TLS Version:", tls_version)

print("\nRecon:")
print("[+] Server:", server)

if robots_found:
    print("[+] robots.txt found")
else:
    print("[!] robots.txt not found")

if sitemap_found:
    print("[+] sitemap.xml found")
    print("[+] URLs discovered:", len(discovered_urls))
else:
    print("[!] sitemap.xml not found")

print("\nPriority Findings:")

if findings:
    for finding in findings:
        if finding == "Content-Security-Policy":
            print("[MEDIUM]", finding, "missing")
            print("         → Content injection/XSS protection may be weaker")

        elif finding == "Strict-Transport-Security":
            print("[LOW]", finding, "missing")
            print("         → HTTPS enforcement is not explicitly configured")

        elif finding == "X-Frame-Options":
            print("[INFO]", finding, "missing")
            print("         → Clickjacking protection is not explicitly configured")

        elif finding == "X-Content-Type-Options":
            print("[INFO]", finding, "missing")
            print("         → MIME-sniffing protection is not explicitly configured")
else:
    print("[+] No security observations found")

print("=======================================")

report_file = "webrecon_report.txt"

with open(report_file, "w", encoding="utf-8") as report:
    report.write("========== WEBRECON REPORT ==========\n\n")
    report.write(f"Target: {target}\n")
    report.write(f"IP Address: {ip_address}\n")
    report.write(f"HTTP Status: {response.status_code}\n")
    report.write(f"TLS Version: {tls_version}\n\n")

    report.write("Recon:\n")
    report.write(f"[+] Server: {server}\n")

    if robots_found:
        report.write("\n--- robots.txt ---\n")
        report.write(robots_content)
        report.write("\n")
    else:
        report.write("[!] robots.txt not found\n")

    if sitemap_found:
        report.write("\n--- Sitemap ---\n")
        report.write("[+] sitemap.xml found\n")

        report.write("\nDiscovered URLs:\n")

        for url in discovered_urls:
            report.write(f"- {url}\n")

    else:
        report.write("[!] sitemap.xml not found\n")

    report.write("\n--- Directory Discovery ---\n")

    if directory_results:
        for result in directory_results:
            report.write(result + "\n")
    else:
        report.write("[+] No interesting directories found\n")

    report.write("\nPriority Findings:\n")

    if findings:
        for finding in findings:
            if finding == "Content-Security-Policy":
                report.write(f"[MEDIUM] {finding} missing\n")
                report.write("         → Content injection/XSS protection may be weaker\n")

            elif finding == "Strict-Transport-Security":
                report.write(f"[LOW] {finding} missing\n")
                report.write("         → HTTPS enforcement is not explicitly configured\n")

            elif finding == "X-Frame-Options":
                report.write(f"[INFO] {finding} missing\n")
                report.write("         → Clickjacking protection is not explicitly configured\n")

            elif finding == "X-Content-Type-Options":
                report.write(f"[INFO] {finding} missing\n")
                report.write("         → MIME-sniffing protection is not explicitly configured\n")
    else:
        report.write("[+] No security observations found\n")

    report.write("=====================================\n")

print(f"\n[+] Report saved to {report_file}")