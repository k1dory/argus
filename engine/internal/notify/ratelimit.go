package notify

import (
	"errors"
	"sync"
	"time"
)

// ErrRateLimited — сообщение отброшено ограничителем: канал уведомлений не
// должен превращать шторм инцидентов в шторм сообщений (и бан у Telegram).
var ErrRateLimited = errors.New("notify: превышен лимит сообщений в минуту, сообщение отброшено")

// Limiter — token bucket: burst сообщений сразу, дальше perMinute в минуту.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // токенов в секунду
	burst  float64
	tokens float64
	last   time.Time
	nowFn  func() time.Time
}

func NewLimiter(perMinute int) *Limiter {
	if perMinute <= 0 {
		perMinute = 20
	}
	l := &Limiter{rate: float64(perMinute) / 60, burst: float64(perMinute), nowFn: time.Now}
	l.tokens = l.burst
	return l
}

// Allow — есть ли токен на отправку прямо сейчас. Точка отсчёта берётся от
// первого вызова (не от конструктора: подменённые в тестах часы иначе
// давали отрицательный интервал); ход часов назад пополнение не отнимает.
func (l *Limiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFn()
	if l.last.IsZero() {
		l.last = now
	}
	if elapsed := now.Sub(l.last); elapsed > 0 {
		l.tokens = min(l.burst, l.tokens+elapsed.Seconds()*l.rate)
		l.last = now // назад точка отсчёта не двигается: ход часов назад не считается временем
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
