# WebRecon

Automated web reconnaissance and vulnerability identification tool built with Python.

WebRecon performs passive and lightweight active reconnaissance against an authorized web target and generates a structured reconnaissance report.

## Features

- DNS / IP address resolution
- HTTP status code detection
- HTTPS and redirect analysis
- TLS version detection
- HTTP header enumeration
- Server information detection
- Technology information checks
- `robots.txt` discovery
- `sitemap.xml` discovery
- Sitemap URL extraction
- Basic directory discovery
- Cookie security analysis
- Security header analysis
- Priority-based findings
- Automatic text report generation

## Technologies Used

- Python 3
- Requests
- Socket programming
- SSL/TLS
- XML parsing
- URL parsing
- Git & GitHub

## Installation

Clone the repository:

```bash
git clone https://github.com/Ishwari0302/automated-web-recon.git
cd automated-web-recon
```
Install the required Python dependency:
```bash
pip install -r requirements.txt
```
## Usage

Run WebRecon:
```bash
python webrecon.py
```
Enter the URL of an authorized target when prompted.
Example:
```bash
Enter target URL: https://www.site-example.com/
```

## Example Output

```text
WebRecon
Automated Web Reconnaissance Tool
Starting...

Enter target URL: https://www.site-example.com/

IP Address: 192.178.x.x
HTTP Status Code: 200

HTTPS / Redirect Analysis:
[+] No redirect detected

TLS Information:
[+] TLS Version: TLSv1.3

Server Information:
[+] Server: Google Frontend

Robots.txt:
[+] robots.txt found

Sitemap:
[+] sitemap.xml found

[+] URLs discovered: 8
```

## Security and Authorization

WebRecon is intended for authorized security testing and reconnaissance only.

Use this tool only against:

- Websites you own
- Systems you have explicit permission to assess
- Intentionally vulnerable security labs and training environments

Do not use WebRecon to scan or test websites without authorization.


## Project Structure

```text
automated-web-recon/
├── webrecon.py
├── requirements.txt
├── webrecon_report.txt
├── .gitignore
└── README.md
```

## Technologies Used

- Python
- Requests
- Socket programming
- DNS resolution
- HTTP/HTTPS
- Git & GitHub