package canal

import "sync"

// KeyedExecutor runs functions exclusively for the same key while allowing
// different keys to run concurrently.
//
// It is the small primitive behind per-table schema serialization: a rebuild or
// row event for table A never waits on table B.
type KeyedExecutor struct {
	mu      sync.Mutex
	keys    map[string]*sync.Mutex
	blocked map[string]int
}

// NewKeyedExecutor creates an empty keyed executor.
func NewKeyedExecutor() *KeyedExecutor {
	return &KeyedExecutor{
		keys:    make(map[string]*sync.Mutex),
		blocked: make(map[string]int),
	}
}

// TableExecutor is an alternative name for KeyedExecutor.
type TableExecutor = KeyedExecutor

// SerialExecutor is an alternative name for KeyedExecutor.
type SerialExecutor = KeyedExecutor

// TableLocks is an alternative name for KeyedExecutor.
type TableLocks = KeyedExecutor

// NewTableExecutor creates a KeyedExecutor under a domain-specific name.
func NewTableExecutor() *KeyedExecutor { return NewKeyedExecutor() }

// NewSerialExecutor creates a KeyedExecutor under another common name.
func NewSerialExecutor() *KeyedExecutor { return NewKeyedExecutor() }

// NewTableLocks creates a keyed lock set.
func NewTableLocks() *KeyedExecutor { return NewKeyedExecutor() }

func (e *KeyedExecutor) mutex(key string) *sync.Mutex {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.keys == nil {
		e.keys = make(map[string]*sync.Mutex)
	}
	m, ok := e.keys[key]
	if !ok {
		m = &sync.Mutex{}
		e.keys[key] = m
	}
	return m
}

// Do executes fn while holding the exclusive lock for key.
func (e *KeyedExecutor) Do(key string, fn func() error) error {
	m := e.mutex(key)
	m.Lock()
	e.setBlocked(key, true)
	defer func() {
		e.setBlocked(key, false)
		m.Unlock()
	}()
	return fn()
}

// Execute is an alias for Do.
func (e *KeyedExecutor) Execute(key string, fn func() error) error {
	return e.Do(key, fn)
}

// Run is an alias for Do that accepts a function without an error result.
func (e *KeyedExecutor) Run(key string, fn func()) {
	_ = e.Do(key, func() error {
		fn()
		return nil
	})
}

// Lock locks the key. Most callers should use Do so unlock is automatic.
func (e *KeyedExecutor) Lock(key string) {
	e.mutex(key).Lock()
	e.setBlocked(key, true)
}

// Unlock unlocks the key.
func (e *KeyedExecutor) Unlock(key string) {
	e.setBlocked(key, false)
	e.mutex(key).Unlock()
}

// IsBlocked reports whether a Do/Lock critical section is active for key.
func (e *KeyedExecutor) IsBlocked(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.blocked[key] > 0
}

func (e *KeyedExecutor) setBlocked(key string, active bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.blocked == nil {
		e.blocked = make(map[string]int)
	}
	if active {
		e.blocked[key]++
	} else {
		e.blocked[key]--
		if e.blocked[key] <= 0 {
			delete(e.blocked, key)
		}
	}
}
