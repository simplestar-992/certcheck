# CertCheck - SSL Certificate Monitor

**Monitor SSL certificate expiration and get alerted before they expire**

CertCheck checks SSL certificates for any domain and alerts you before they expire. Perfect for DevOps teams managing multiple domains.

## Features

- **Fast SSL Checking** - Check hundreds of domains in seconds
- **Expiration Alerts** - Get warned before certificates expire
- **Email Notifications** - Send alerts via SMTP
- **Webhook Support** - Integrate with Slack, PagerDuty, etc.
- **Daemon Mode** - Run continuously and check on schedule
- **JSON Export** - Export results for integration
- **Color Output** - Easy to read in terminal

## Installation

```bash
# Download binary for your platform
curl -sSL https://github.com/YOUR_HANDLE/certcheck/releases/latest | sh

# Or build from source
git clone https://github.com/YOUR_HANDLE/certcheck.git
cd certcheck
go build -o certcheck .
```

## Usage

```bash
# Check single domain
./certcheck -d example.com

# Check multiple domains
./certcheck -d example.com,google.com,github.com

# Check from file
./certcheck -f domains.txt

# Check with stdin
cat domains.txt | ./certcheck

# Daemon mode (check every 24 hours)
./certcheck -f domains.txt --daemon --interval 24h

# With email alerts
./certcheck -f domains.txt --email admin@example.com --smtp-host smtp.gmail.com --smtp-user user --smtp-pass pass
```

## Options

```
-d string        Comma-separated domains
-f string        File with domains (one per line)
--json string    Output JSON file
--warn int       Days before expiry to warn (default: 30)
--daemon         Run continuously
--interval       Check interval (default: 24h)
--email          Email to send alerts
--smtp-host      SMTP host
--smtp-port      SMTP port (default: 587)
--smtp-user      SMTP username
--smtp-pass      SMTP password
```

## Examples

```bash
# Quick check
./certcheck -d stripe.com,paypal.com

# CI/CD integration
./certcheck -d api.example.com | grep EXPIRING && exit 1

# Slack webhook
curl -X POST https://hooks.slack.com/... -d '{"text":"Cert expiring!"}'
```

##domains.txt format
```
# Comment
example.com
api.example.com:8443
*.wildcard.com
```

## License

MIT
