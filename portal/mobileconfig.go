package portal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"strings"
)

// iOS has no user interface for DNS-over-TLS. Android exposes it directly under
// Private DNS, but on iOS the only way to configure an encrypted resolver is a
// configuration profile: a signed or unsigned plist the user installs through
// Settings.
//
// That makes this file load-bearing. Without it, every iPhone customer is a
// support conversation, and iPhones are common among the expatriate workers
// this product is aimed at.

// MobileConfig describes the profile to generate.
type MobileConfig struct {
	// Hostname is the tenant's own resolver name, which is what carries the
	// identity in the TLS SNI.
	Hostname string

	// DisplayName and Organization appear in Settings when the customer
	// inspects what they installed.
	DisplayName  string
	Organization string

	// Identifier is the reverse-DNS profile identifier. Reusing it means a
	// reinstall replaces the old profile rather than stacking a second one.
	Identifier string

	// Description is shown on the install screen.
	Description string
}

// Generate renders an unsigned .mobileconfig.
//
// Unsigned profiles install correctly; iOS shows the profile as "Unverified"
// on the confirmation screen. Signing requires an Apple-issued certificate,
// which is a business decision rather than a technical one, so the profile is
// produced unsigned here and the structure left ready to sign.
func (m MobileConfig) Generate() ([]byte, error) {
	if m.Hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}
	if !validHostname(m.Hostname) {
		return nil, fmt.Errorf("invalid hostname")
	}

	if m.DisplayName == "" {
		m.DisplayName = "Private DNS"
	}
	if m.Organization == "" {
		m.Organization = "PrivateDNS"
	}
	if m.Identifier == "" {
		m.Identifier = "io.privatedns.profile"
	}
	if m.Description == "" {
		m.Description = "Encrypted DNS with filtering."
	}

	// Deriving the UUIDs from the hostname keeps them stable across
	// regenerations, so reinstalling replaces the existing profile instead of
	// leaving two that fight over the same setting.
	profileUUID := stableUUID(m.Hostname + "|profile")
	payloadUUID := stableUUID(m.Hostname + "|dns")

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	b.WriteString("<dict>\n")

	b.WriteString("\t<key>PayloadContent</key>\n\t<array>\n\t\t<dict>\n")
	b.WriteString("\t\t\t<key>PayloadType</key>\n\t\t\t<string>com.apple.dnsSettings.managed</string>\n")
	b.WriteString("\t\t\t<key>PayloadVersion</key>\n\t\t\t<integer>1</integer>\n")
	writeKV(&b, 3, "PayloadIdentifier", m.Identifier+".dns")
	writeKV(&b, 3, "PayloadUUID", payloadUUID)
	writeKV(&b, 3, "PayloadDisplayName", m.DisplayName)

	b.WriteString("\t\t\t<key>DNSSettings</key>\n\t\t\t<dict>\n")
	// TLS, not HTTPS: DoT carries the tenant in the SNI, which is how the
	// resolver knows whose policy to apply.
	writeKV(&b, 4, "DNSProtocol", "TLS")
	writeKV(&b, 4, "ServerName", m.Hostname)
	b.WriteString("\t\t\t</dict>\n")

	// Applying on both cellular and Wi-Fi is the point: a customer abroad
	// switches between them constantly, and a profile that only covered one
	// would look intermittent rather than broken.
	b.WriteString("\t\t\t<key>ProhibitDisablement</key>\n\t\t\t<false/>\n")
	b.WriteString("\t\t</dict>\n\t</array>\n")

	writeKV(&b, 1, "PayloadDisplayName", m.DisplayName)
	writeKV(&b, 1, "PayloadDescription", m.Description)
	writeKV(&b, 1, "PayloadIdentifier", m.Identifier)
	writeKV(&b, 1, "PayloadOrganization", m.Organization)
	writeKV(&b, 1, "PayloadUUID", profileUUID)
	b.WriteString("\t<key>PayloadType</key>\n\t<string>Configuration</string>\n")
	b.WriteString("\t<key>PayloadVersion</key>\n\t<integer>1</integer>\n")
	// Not removable would trap a customer whose subscription lapses.
	b.WriteString("\t<key>PayloadRemovalDisallowed</key>\n\t<false/>\n")

	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes(), nil
}

// Filename is what the browser should save the profile as.
func (m MobileConfig) Filename() string {
	label := strings.SplitN(m.Hostname, ".", 2)[0]
	if label == "" {
		label = "privatedns"
	}
	return label + ".mobileconfig"
}

func writeKV(b *bytes.Buffer, indent int, key, value string) {
	tabs := strings.Repeat("\t", indent)
	// Escaping matters: the hostname is derived from stored data, and an
	// unescaped angle bracket would break the plist or inject an element.
	fmt.Fprintf(b, "%s<key>%s</key>\n%s<string>%s</string>\n",
		tabs, html.EscapeString(key), tabs, html.EscapeString(value))
}

// stableUUID derives a deterministic RFC 4122-shaped identifier from a seed.
func stableUUID(seed string) string {
	sum := sha256.Sum256([]byte("privatedns:" + seed))
	h := hex.EncodeToString(sum[:16])

	// Stamp version 4 and the RFC 4122 variant so the value is well-formed.
	b := []byte(h)
	b[12] = '4'
	switch b[16] {
	case '0', '1', '2', '3', '4', '5', '6', '7':
		b[16] = '8'
	}
	h = string(b)

	return strings.ToUpper(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32])
}

// validHostname mirrors the resolver's rules. The hostname reaches a plist a
// customer installs into their device's network settings, so anything odd is
// refused rather than rendered.
func validHostname(h string) bool {
	if h == "" || len(h) > 253 || strings.HasSuffix(h, ".") {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
