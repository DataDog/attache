package synchronization

import "context"

type CancellableLock struct {
	lockChan chan struct{}
}

func NewCancellableLock() *CancellableLock {
	lock := &CancellableLock{
		lockChan: make(chan struct{}, 1),
	}
	lock.Unlock()
	return lock
}

func (l *CancellableLock) Lock() {
	<-l.lockChan
}

// lockIfNotCancelled is attempting to take the lock but gives up if the context is cancelled
// This allows putting a time limit on the lock, as well as locking within a cancellable call
// lockIfNotCancelled returns an error if the ctx was cancelled (without taking the lock), otherwise returns nil
// user must call unlock to release the lock iif the error returned is nil
func (l *CancellableLock) LockIfNotCancelled(ctx context.Context) error {
	select {
	case <-l.lockChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *CancellableLock) Unlock() {
	l.lockChan <- struct{}{}
}
