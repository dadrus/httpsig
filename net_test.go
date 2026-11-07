package httpsig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitHostPort(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		input string
		host  string
		port  string
		valid bool
	}{
		"domain without port":            {input: "EXAMPLE.com", host: "EXAMPLE.com", valid: true},
		"domain with port":               {input: "EXAMPLE.com:0443", host: "EXAMPLE.com", port: "0443", valid: true},
		"domain with empty port":         {input: "EXAMPLE.com:", host: "EXAMPLE.com", valid: true},
		"ipv6 without port":              {input: "[2001:DB8::1]", host: "[2001:DB8::1]", valid: true},
		"ipv6 with port":                 {input: "[2001:DB8::1]:443", host: "[2001:DB8::1]", port: "443", valid: true},
		"ipv6 with empty port":           {input: "[2001:DB8::1]:", host: "[2001:DB8::1]", valid: true},
		"invalid ipv6 encoded zone":      {input: "[fe80::1%25eth0]"},
		"invalid ipv6 encoded zone case": {input: "[fe80::1%25ETH0]"},
		"ipvfuture":                      {input: "[v1.a:2]", host: "[v1.a:2]", valid: true},
		"percent-encoded reg-name":       {input: "exa%6Dple.com", host: "exa%6Dple.com", valid: true},
		"invalid empty authority":        {input: ""},
		"invalid empty hostname":         {input: ":80"},
		"invalid alpha port":             {input: "example.com:abc"},
		"invalid signed port":            {input: "example.com:+80"},
		"invalid unbracketed ipv6":       {input: "2001:db8::1"},
		"invalid ipv6":                   {input: "[not-ipv6]"},
		"invalid missing bracket":        {input: "[2001:db8::1"},
		"invalid ipvfuture":              {input: "[v.no]"},
		"invalid zone encoding":          {input: "[fe80::1%eth0]"},
		"invalid userinfo":               {input: "user@example.com"},
		"invalid path":                   {input: "example.com/path"},
		"invalid percent escape":         {input: "exa%GGmple.com"},
		"invalid non-ASCII":              {input: "exämple.com"},
	} {
		t.Run(name, func(t *testing.T) {
			host, port, valid := splitHostPort(tc.input)
			assert.Equal(t, tc.valid, valid)
			assert.Equal(t, tc.host, host)
			assert.Equal(t, tc.port, port)
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		input string
		want  string
	}{
		"plain lowercase":              {input: "example.com", want: "example.com"},
		"mixed case":                   {input: "EXAMPLE.COM", want: "example.com"},
		"percent-encoded letter":       {input: "EXA%6Dple.COM", want: "example.com"},
		"percent-encoded capital":      {input: "EX%41MPLE.COM", want: "example.com"},
		"percent-encoded tilde":        {input: "EXA%7Emple.COM", want: "exa~mple.com"},
		"percent-encoded dot":          {input: "EXAMPLE%2eCOM", want: "example.com"},
		"percent-encoded reserved":     {input: "EXAMPLE%2f.COM", want: "example%2F.com"},
		"percent-encoded non-ASCII":    {input: "EXAMPLE%C3%a4.COM", want: "example%C3%A4.com"},
		"do not double-decode percent": {input: "EXAMPLE%256d.COM", want: "example%256d.com"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeHost(tc.input))
		})
	}
}
