package storage

import (
	"context"
	"sort"
	"strings"
	"sync"
)

// MemoryStore is an in-memory ObjectStore for tests, cmd/devserver, and local
// experimentation. It retains every object in a map and is not a production
// backend (it grows without bound). It is safe for concurrent use.
type MemoryStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{objects: make(map[string][]byte)}
}

// Put stores a copy of data at key.
func (m *MemoryStore) Put(_ context.Context, key string, data []byte) error {
	cp := append([]byte(nil), data...)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = cp
	return nil
}

// Get returns a copy of the object at key, or ErrNotFound.
func (m *MemoryStore) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), data...), nil
}

// List returns the stored keys that start with prefix, in sorted order. A prefix
// of "" lists every key (equivalent to Keys).
func (m *MemoryStore) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Delete removes the object at key. Deleting an absent key is a no-op (nil),
// matching R2's idempotent delete so a retried transition behaves identically.
func (m *MemoryStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	return nil
}

// Keys returns the stored object keys in sorted order (test/ops helper).
func (m *MemoryStore) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.objects))
	for k := range m.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Len reports how many objects are stored.
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.objects)
}

var _ ObjectStore = (*MemoryStore)(nil)
