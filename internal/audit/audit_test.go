package audit

import "testing"

func TestBucket(t *testing.T) {
	tests := []struct{ ip, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"::ffff:203.0.113.7", "::ffff:203.0.113.7"},
		{"", ""},
		{"lixo", "lixo"},
	}
	for _, tt := range tests {
		if got := (Client{IP: tt.ip}).Bucket(); got != tt.want {
			t.Errorf("Bucket(%q) = %q, esperado %q", tt.ip, got, tt.want)
		}
	}
}
