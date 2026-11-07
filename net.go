package httpsig

import (
	"net/netip"
	"strings"
)

// splitHostPort splits an HTTP authority into a validated host (including
// IP-literal brackets) and an optional port. Userinfo, paths, queries, and
// fragments are not permitted.
//
//nolint:cyclop
func splitHostPort(authority string) (string, string, bool) {
	if authority == "" {
		return "", "", false
	}

	var (
		host string
		port string
	)

	if authority[0] == '[' { //nolint:nestif
		end := strings.IndexByte(authority, ']')
		if end == -1 {
			return "", "", false
		}

		if !validIPLiteral(authority[1:end]) {
			return "", "", false
		}

		host = authority[:end+1]
		if end+1 < len(authority) {
			if authority[end+1] != ':' {
				return "", "", false
			}

			port = authority[end+2:]
		}
	} else {
		if before, after, ok := strings.Cut(authority, ":"); ok {
			host, port = before, after
		} else {
			host = authority
		}

		if !validAuthorityRegName(host) {
			return "", "", false
		}
	}

	for i := range len(port) {
		if port[i] < '0' || port[i] > '9' {
			return "", "", false
		}
	}

	return host, port, true
}

// normalizeHost applies HTTP URI case and percent-encoding
// normalization to a host already validated by splitHostPort.
//
//nolint:cyclop
func normalizeHost(host string) string {
	if strings.HasPrefix(host, "[") || !strings.Contains(host, "%") {
		return strings.ToLower(host)
	}

	const upperHex = "0123456789ABCDEF"

	var normalized strings.Builder
	normalized.Grow(len(host))

	for i := 0; i < len(host); i++ {
		ch := host[i]
		if ch == '%' {
			decoded := hexValue(host[i+1])<<4 | hexValue(host[i+2]) //nolint:mnd
			if (decoded >= 'a' && decoded <= 'z') ||
				(decoded >= 'A' && decoded <= 'Z') ||
				(decoded >= '0' && decoded <= '9') ||
				decoded == '-' || decoded == '.' || decoded == '_' || decoded == '~' {
				ch = decoded
			} else {
				normalized.WriteByte('%')
				normalized.WriteByte(upperHex[decoded>>4])
				normalized.WriteByte(upperHex[decoded&0x0f])

				i += 2

				continue
			}

			i += 2
		}

		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}

		normalized.WriteByte(ch)
	}

	return normalized.String()
}

// hexValue converts a validated ASCII hex digit to its numeric value.
func hexValue(ch byte) byte {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0'
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10 //nolint:mnd
	default:
		return ch - 'a' + 10 //nolint:mnd
	}
}

func validIPLiteral(literal string) bool {
	ip, err := netip.ParseAddr(literal)
	if err == nil {
		return ip.Is6() && ip.Zone() == ""
	}

	return validIPvFuture(literal)
}

func validAuthorityRegName(name string) bool {
	if name == "" {
		return false
	}

	for i := 0; i < len(name); i++ {
		ch := name[i]
		if isRegNameChar(ch) {
			continue
		}

		if ch != '%' || i+2 >= len(name) || !isHexDigit(name[i+1]) || !isHexDigit(name[i+2]) {
			return false
		}

		i += 2
	}

	return true
}

//nolint:cyclop
func validIPvFuture(literal string) bool {
	if len(literal) < 4 || (literal[0] != 'v' && literal[0] != 'V') {
		return false
	}

	i := 1
	for i < len(literal) && isHexDigit(literal[i]) {
		i++
	}

	if i == 1 || i >= len(literal)-1 || literal[i] != '.' {
		return false
	}

	for i++; i < len(literal); i++ {
		if !isRegNameChar(literal[i]) && literal[i] != ':' {
			return false
		}
	}

	return true
}

func isRegNameChar(ch byte) bool {
	if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
		return true
	}

	switch ch {
	case '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=':
		return true
	}

	return false
}

func isHexDigit(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}
