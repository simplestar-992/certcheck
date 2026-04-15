# CertCheck | SSL Certificate Monitoring Tool

![SSL Monitor](https://img.shields.io/badge/Purpose-SSL%20Certificate%20Monitor-blue?style=for-the-badge)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## Overview

Never let an SSL certificate expire unexpectedly again. CertCheck monitors your certificates and alerts you before they expire.

**Perfect for:**
- DevOps engineers managing multiple domains
- System administrators tracking certificate expiration
- Security teams ensuring proper TLS configuration
- Anyone managing production infrastructure

---

## Features

- **Multi-domain support** - Check multiple domains at once
- **Expiration tracking** - Days until expiration, sorted by urgency
- **Webhook alerts** - Get notified before certificates expire
- **Detailed certificate info** - Issuer, validity period, chain details
- **JSON output** - Integrate with monitoring systems
- **Lightweight** - Single binary, no dependencies

---

## Installation

```bash
# Build from source
git clone https://github.com/simplestar-992/certcheck.git
cd certcheck
go build -o certcheck -ldflags="-s -w"

# Run directly
./certcheck -d example.com
```

---

## Usage

### Basic Commands

```bash
# Check single domain
./certcheck -d example.com

# Check multiple domains
./certcheck -d example.com,github.com,google.com

# Check with file input
./certcheck -f domains.txt

# Enable webhook notifications
./certcheck -d example.com -webhook https://hooks.slack.com/xxx
```

### Real-World Examples

```bash
# Monitor your infrastructure
./certcheck -f /etc/certcheck/domains.txt -json output.json

# Cron job for daily checks
0 0 * * * /usr/local/bin/certcheck -f ~/domains.txt -webhook $SLACK_WEBHOOK

# Quick health check
./certcheck -d api.example.com,cdn.example.com,app.example.com
```

---

## Output

```
🔍 CertCheck - SSL Certificate Monitor
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ example.com
  ├─ Issuer: Let's Encrypt Authority X3
  ├─ Valid Until: 2024-06-15 (45 days)
  ├─ Algorithm: RSA 2048
  └─ ✓ Certificate OK

⚠️ expired-soon.com
  ├─ Issuer: DigiCert Inc
  ├─ Valid Until: 2024-04-20 (2 days!)
  ├─ Algorithm: RSA 4096
  └─ ⚠️ EXPIRING SOON - Renew immediately!

✗ api.missing-cert.com
  └─ Connection failed - Certificate not found
```

---

## Configuration

Create a `domains.txt` file:

```
example.com
github.com
api.example.com
cdn.example.com
```

---

## License

MIT © 2024 [simplestar-992](https://github.com/simplestar-992)
