package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	period    = 30
	digits    = 6
	secretLen = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

var pow10 = [...]uint32{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

func newSecret() []byte {
	s := make([]byte, secretLen)
	_, _ = rand.Read(s)
	return s
}

func hotp(secret []byte, counter uint64, n int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", n, bin%pow10[n])
}

func step(t time.Time) int64 {
	return t.Unix() / period
}

func validate(secret []byte, code string, now time.Time) (int64, bool) {
	if len(code) != digits {
		return 0, false
	}
	current := step(now)
	for _, s := range []int64{current - 1, current, current + 1} {
		if s < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(s), digits)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

func otpauthURI(issuer, account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", b32.EncodeToString(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(digits))
	q.Set("period", fmt.Sprint(period))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + q.Encode()
}
