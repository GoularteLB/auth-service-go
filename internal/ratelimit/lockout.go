package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var failScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ARGV[1])
local threshold = tonumber(ARGV[2])
if n < threshold then
  return 0
end
local d = tonumber(ARGV[3])
local max = tonumber(ARGV[4])
for i = 1, n - threshold do
  d = d * 2
  if d >= max then
    d = max
    break
  end
end
redis.call('SET', KEYS[2], '1', 'PX', d)
return d
`)

type LockoutPolicy struct {
	Threshold int
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Memory    time.Duration
}

var DefaultLockoutPolicy = LockoutPolicy{
	Threshold: 5,
	BaseDelay: time.Minute,
	MaxDelay:  15 * time.Minute,
	Memory:    time.Hour,
}

type Lockout struct {
	rdb    *redis.Client
	policy LockoutPolicy
}

func NewLockout(rdb *redis.Client, policy LockoutPolicy) *Lockout {
	return &Lockout{rdb: rdb, policy: policy}
}

func (l *Lockout) Check(ctx context.Context, key string) (time.Duration, error) {
	ttl, err := l.rdb.PTTL(ctx, lockKey(key)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return 0, fmt.Errorf("consultando bloqueio: %w", err)
	}
	if ttl <= 0 {
		return 0, nil
	}
	return ttl, nil
}

func (l *Lockout) Fail(ctx context.Context, key string) (time.Duration, error) {
	p := l.policy
	ms, err := failScript.Run(ctx, l.rdb,
		[]string{failKey(key), lockKey(key)},
		p.Memory.Milliseconds(), p.Threshold, p.BaseDelay.Milliseconds(), p.MaxDelay.Milliseconds(),
	).Int64()
	if err != nil {
		return 0, fmt.Errorf("registrando falha: %w", err)
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func (l *Lockout) Reset(ctx context.Context, key string) error {
	if err := l.rdb.Del(ctx, failKey(key), lockKey(key)).Err(); err != nil {
		return fmt.Errorf("limpando bloqueio: %w", err)
	}
	return nil
}

func failKey(key string) string {
	return hashKey("lockout:fails:", key)
}

func lockKey(key string) string {
	return hashKey("lockout:until:", key)
}
