package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var windowScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {n, ttl}
`)

type Limiter struct {
	rdb *redis.Client
}

func NewLimiter(rdb *redis.Client) *Limiter {
	return &Limiter{rdb: rdb}
}

func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (time.Duration, error) {
	res, err := windowScript.Run(ctx, l.rdb, []string{hashKey("ratelimit:", key)}, window.Milliseconds()).Int64Slice()
	if err != nil {
		return 0, fmt.Errorf("rate limit: %w", err)
	}
	if res[0] <= int64(limit) {
		return 0, nil
	}
	return time.Duration(res[1]) * time.Millisecond, nil
}

func hashKey(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return prefix + base64.RawURLEncoding.EncodeToString(sum[:])
}
