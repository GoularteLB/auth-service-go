package httpserver

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
	tests := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"direto", "203.0.113.5:1234", nil, "203.0.113.5"},
		{"ignora xff de cliente não confiável", "203.0.113.5:1234", []string{"1.2.3.4"}, "203.0.113.5"},
		{"proxy confiável", "10.0.0.2:80", []string{"203.0.113.9"}, "203.0.113.9"},
		{"ignora valor forjado à esquerda", "10.0.0.2:80", []string{"6.6.6.6, 203.0.113.9"}, "203.0.113.9"},
		{"vários proxies confiáveis", "10.0.0.2:80", []string{"203.0.113.9, 10.1.1.1", "10.2.2.2"}, "203.0.113.9"},
		{"xff inválido para no último válido", "10.0.0.2:80", []string{"lixo, 10.1.1.1"}, "10.1.1.1"},
		{"proxy sem xff", "10.0.0.2:80", nil, "10.0.0.2"},
		{"ipv6 confiável", "[::1]:80", []string{"2001:db8::1"}, "2001:db8::1"},
		{"ipv4 mapeado em ipv6", "[::ffff:203.0.113.5]:80", nil, "203.0.113.5"},
		{"remote inválido", "sem-porta", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := clientIP(r, trusted); got != tt.want {
				t.Errorf("clientIP = %q, esperado %q", got, tt.want)
			}
		})
	}
}
