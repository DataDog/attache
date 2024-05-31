package rate

// Token bucket rate limiter from the x/time/rate golang library.
// Alterations include:
// - Limiter.WaitNWithCallback allowing callers to obtain the
//   time.Duration for which a request is rate limited.
