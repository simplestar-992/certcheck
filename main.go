package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"time"
)

type CertInfo struct {
	Domain      string    `json:"domain"`
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	Expired     bool      `json:"expired"`
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
}

func checkCert(domain, port string) (*CertInfo, error) {
	if port == "" {
		port = "443"
	}

	address := domain + ":" + port

	conn, err := tls.Dial("tcp", address, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]

	return &CertInfo{
		Domain:     domain,
		Issuer:     cert.Issuer.String(),
		Subject:    cert.Subject.String(),
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		DaysLeft:   int(time.Until(cert.NotAfter).Hours() / 24),
		Expired:    time.Now().After(cert.NotAfter),
		Serial:     cert.SerialNumber.String(),
	}, nil
}

func (c *CertInfo) GetIssuerCommonName() string {
	parts := strings.Split(c.Issuer, ",")
	for _, p := range parts {
		if strings.HasPrefix(strings.TrimSpace(p), "CN=") {
			return strings.TrimPrefix(strings.TrimSpace(p), "CN=")
		}
	}
	return c.Issuer
}

func checkAllCerts(domains []string, warnDays int) ([]CertInfo, []CertInfo) {
	var all, expiring []CertInfo

	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}

		port := ""
		if strings.Contains(domain, ":") {
			parts := strings.Split(domain, ":")
			domain = parts[0]
			port = parts[1]
		}

		cert, err := checkCert(domain, port)
		if err != nil {
			fmt.Printf("❌ %s: %v\n", domain, err)
			continue
		}

		all = append(all, *cert)

		if cert.DaysLeft <= warnDays {
			expiring = append(expiring, *cert)
		}

		status := "✅"
		if cert.Expired {
			status = "🔴 EXPIRED"
		} else if cert.DaysLeft <= warnDays {
			status = "⚠️  EXPIRING"
		}

		fmt.Printf("%s %-40s %s (expires %s, %d days)\n",
			status, domain, cert.GetIssuerCommonName(),
			cert.NotAfter.Format("2006-01-02"), cert.DaysLeft)
	}

	return all, expiring
}

func loadDomainsFromFile(filepath string) ([]string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var domains []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains, nil
}

func exportJSON(filepath string, certs []CertInfo) error {
	data, err := json.MarshalIndent(certs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0644)
}

func sendAlert(email, smtpHost, smtpPort, smtpUser, smtpPass string, certs []CertInfo) error {
	if len(certs) == 0 || email == "" {
		return nil
	}

	var body strings.Builder
	body.WriteString("From: CertCheck <alerts@certcheck.io>\n")
	body.WriteString("To: " + email + "\n")
	body.WriteString("Subject: ⚠️ SSL Certificate Alert\n")
	body.WriteString("Content-Type: text/html; charset=UTF-8\n\n")
	body.WriteString("<html><body>")
	body.WriteString("<h2>⚠️ SSL Certificate Alert</h2>")
	body.WriteString("<p>The following certificates are expiring soon:</p>")
	body.WriteString("<table border='1' cellpadding='8' style='border-collapse:collapse;'>")
	body.WriteString("<tr><th>Domain</th><th>Expires</th><th>Days Left</th><th>Issuer</th></tr>")

	for _, cert := range certs {
		bg := "#ffcccc"
		if cert.DaysLeft > 7 {
			bg = "#fff3cd"
		}
		body.WriteString(fmt.Sprintf("<tr style='background:%s'><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>",
			bg, cert.Domain, cert.NotAfter.Format("2006-01-02"), cert.DaysLeft, cert.GetIssuerCommonName()))
	}

	body.WriteString("</table></body></html>")

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, "alerts@certcheck.io", []string{email}, []byte(body.String()))

	return err
}

func webhookNotify(webhooks []string, certs []CertInfo) error {
	if len(certs) == 0 || len(webhooks) == 0 {
		return nil
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"alert": "cert_expiring",
		"count": len(certs),
		"certs": certs,
		"time":  time.Now().Format(time.RFC3339),
	})

	for _, webhook := range webhooks {
		resp, err := http.Post(webhook, "application/json", strings.NewReader(string(payload)))
		if err != nil {
			fmt.Printf("Webhook failed: %v\n", err)
		} else {
			resp.Body.Close()
		}
	}

	return nil
}

func generateReport(certs []CertInfo) string {
	var report strings.Builder

	report.WriteString("\n╔══════════════════════════════════════════════════════════════════╗\n")
	report.WriteString("║                   📜 CERTIFICATE REPORT                         ║\n")
	report.WriteString("╠══════════════════════════════════════════════════════════════════╣\n")
	report.WriteString(fmt.Sprintf("║ Generated: %s                                        ║\n", time.Now().Format("2006-01-02 15:04:05")))
	report.WriteString("╠══════════════════════════════════════════════════════════════════╣\n")

	sort.Slice(certs, func(i, j int) bool {
		return certs[i].DaysLeft < certs[j].DaysLeft
	})

	for _, cert := range certs {
		status := "✅ Valid"
		if cert.Expired {
			status = "🔴 EXPIRED"
		} else if cert.DaysLeft <= 7 {
			status = "🔴 Critical"
		} else if cert.DaysLeft <= 30 {
			status = "⚠️  Warning"
		}

		report.WriteString(fmt.Sprintf("║ %-58s ║\n", fmt.Sprintf("%s %s", status, cert.Domain)))
		report.WriteString(fmt.Sprintf("║   Expires: %s (%d days)                              ║\n", cert.NotAfter.Format("2006-01-02"), cert.DaysLeft))
		report.WriteString(fmt.Sprintf("║   Issuer: %-50s ║\n", cert.GetIssuerCommonName()))
		report.WriteString("║                                                                   ║\n")
	}

	report.WriteString("╚══════════════════════════════════════════════════════════════════╝\n")

	return report.String()
}

func main() {
	domainsFile := flag.String("f", "", "File with domains (one per line)")
	domainsFlag := flag.String("d", "", "Comma-separated domains")
	jsonOut := flag.String("json", "", "Output JSON file")
	email := flag.String("email", "", "Email to send alerts")
	smtpHost := flag.String("smtp-host", "", "SMTP host")
	smtpPort := flag.String("smtp-port", "587", "SMTP port")
	smtpUser := flag.String("smtp-user", "", "SMTP user")
	smtpPass := flag.String("smtp-pass", "", "SMTP password")
	warnDays := flag.Int("warn", 30, "Days before expiry to warn")
	daemon := flag.Bool("daemon", false, "Run as daemon")
	interval := flag.Duration("interval", 24*time.Hour, "Check interval")
	flag.Parse()

	var domains []string

	if *domainsFile != "" {
		d, err := loadDomainsFromFile(*domainsFile)
		if err != nil {
			fmt.Printf("Failed to load domains: %v\n", err)
			os.Exit(1)
		}
		domains = d
	}

	if *domainsFlag != "" {
		domains = append(domains, strings.Split(*domainsFlag, ",")...)
	}

	if len(domains) == 0 {
		data, _ := io.ReadAll(os.Stdin)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				domains = append(domains, line)
			}
		}
	}

	if len(domains) == 0 {
		fmt.Println("CertCheck - SSL Certificate Monitor")
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Println("  certcheck -d example.com,google.com")
		fmt.Println("  certcheck -f domains.txt")
		fmt.Println("  echo 'example.com' | certcheck")
		fmt.Println("")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Println("🔍 CertCheck - SSL Certificate Monitor")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("")

	runCheck := func() {
		all, expiring := checkAllCerts(domains, *warnDays)

		if *jsonOut != "" {
			exportJSON(*jsonOut, all)
			fmt.Printf("📄 JSON saved to %s\n", *jsonOut)
		}

		if len(expiring) > 0 {
			fmt.Println("\n⚠️  ALERT: Expiring certificates detected!")
			fmt.Print(generateReport(expiring))

			if *email != "" && *smtpHost != "" {
				if err := sendAlert(*email, *smtpHost, *smtpPort, *smtpUser, *smtpPass, expiring); err != nil {
					fmt.Printf("Failed to send email: %v\n", err)
				} else {
					fmt.Printf("📧 Alert sent to %s\n", *email)
				}
			}
		}
	}

	if *daemon {
		fmt.Printf("🔄 Running in daemon mode (checking every %v)\n", *interval)
		ticker := time.NewTicker(*interval)
		runCheck()
		for range ticker.C {
			runCheck()
		}
	} else {
		runCheck()
	}
}