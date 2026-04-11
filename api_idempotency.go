package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type idempotencyResult struct {
	status int
	body   []byte
}

type idempotencyCache struct {
	mu          sync.Mutex
	ttl         time.Duration
	maxEntries  int
	entries     map[string]*idempotencyEntry
	persistPath string
}

type idempotencyEntry struct {
	createdAt time.Time
	reqHash   [32]byte
	inFlight  bool
	result    idempotencyResult
}

type persistedIdempotencyEntry struct {
	CreatedAtUnixNano int64  `json:"created_at_unix_nano"`
	ReqHashHex        string `json:"req_hash_hex"`
	Status            int    `json:"status"`
	BodyBase64        string `json:"body_base64"`
}

type persistedIdempotencyState struct {
	Entries map[string]persistedIdempotencyEntry `json:"entries"`
}

func newIdempotencyCache(ttl time.Duration, maxEntries int, persistPath string) *idempotencyCache {
	c := &idempotencyCache{
		ttl:         ttl,
		maxEntries:  maxEntries,
		entries:     make(map[string]*idempotencyEntry),
		persistPath: persistPath,
	}
	c.loadPersisted()
	return c
}

func (c *idempotencyCache) getOrStart(now time.Time, key string, reqHash [32]byte) (state string, res idempotencyResult) {
	// state:
	// - "replay": res is valid
	// - "start": caller should process request and then complete()
	// - "inflight": same key currently running
	// - "mismatch": key exists but request differs
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneLocked(now)

	if e, ok := c.entries[key]; ok {
		if e.reqHash != reqHash {
			return "mismatch", idempotencyResult{}
		}
		if e.inFlight {
			return "inflight", idempotencyResult{}
		}
		return "replay", e.result
	}

	c.entries[key] = &idempotencyEntry{
		createdAt: now,
		reqHash:   reqHash,
		inFlight:  true,
	}
	c.enforceCapLocked()
	return "start", idempotencyResult{}
}

func (c *idempotencyCache) complete(now time.Time, key string, reqHash [32]byte, status int, body []byte) {
	c.mu.Lock()

	c.pruneLocked(now)

	e, ok := c.entries[key]
	if !ok {
		c.mu.Unlock()
		return
	}
	if e.reqHash != reqHash {
		delete(c.entries, key)
		c.mu.Unlock()
		return
	}
	e.createdAt = now
	e.inFlight = false
	e.result = idempotencyResult{status: status, body: append([]byte(nil), body...)}
	c.enforceCapLocked()
	data, path := c.snapshotForPersist()
	c.mu.Unlock()

	if err := writePersistData(data, path); err != nil {
		log.Printf("Warning: failed to persist idempotency cache: %v", err)
	}
}

func (c *idempotencyCache) abandon(key string) {
	c.mu.Lock()
	if _, ok := c.entries[key]; !ok {
		c.mu.Unlock()
		return
	}
	delete(c.entries, key)
	data, path := c.snapshotForPersist()
	c.mu.Unlock()

	if err := writePersistData(data, path); err != nil {
		log.Printf("Warning: failed to persist idempotency cache: %v", err)
	}
}

func (c *idempotencyCache) pruneLocked(now time.Time) {
	if c.ttl <= 0 {
		return
	}
	for k, e := range c.entries {
		// Never expire in-flight entries; dropping them re-allows duplicate processing.
		if e.inFlight {
			continue
		}
		if now.Sub(e.createdAt) > c.ttl {
			delete(c.entries, k)
		}
	}
}

func (c *idempotencyCache) enforceCapLocked() {
	if c.maxEntries <= 0 || len(c.entries) <= c.maxEntries {
		return
	}

	// Evict oldest completed entries first.
	// Never evict in-flight entries; callers use those to prevent duplicate processing.
	for len(c.entries) > c.maxEntries {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, e := range c.entries {
			if e.inFlight {
				continue
			}
			if first || e.createdAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = e.createdAt
				first = false
			}
		}
		if oldestKey == "" {
			// All remaining entries are in-flight; keep them even if we're over cap.
			return
		}
		delete(c.entries, oldestKey)
	}
}

func hashRequestBody(body []byte) [32]byte {
	return sha256.Sum256(body)
}

func (c *idempotencyCache) loadPersisted() {
	if c.persistPath == "" {
		return
	}

	data, err := os.ReadFile(c.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Printf("Warning: failed to read idempotency cache %s: %v", c.persistPath, err)
		return
	}

	var persisted persistedIdempotencyState
	if err := json.Unmarshal(data, &persisted); err != nil {
		log.Printf("Warning: failed to parse idempotency cache %s: %v", c.persistPath, err)
		return
	}

	now := time.Now()
	for key, entry := range persisted.Entries {
		reqHashBytes, err := hex.DecodeString(entry.ReqHashHex)
		if err != nil || len(reqHashBytes) != sha256.Size {
			continue
		}
		body, err := base64.StdEncoding.DecodeString(entry.BodyBase64)
		if err != nil {
			continue
		}

		var reqHash [32]byte
		copy(reqHash[:], reqHashBytes)
		c.entries[key] = &idempotencyEntry{
			createdAt: time.Unix(0, entry.CreatedAtUnixNano),
			reqHash:   reqHash,
			inFlight:  false,
			result: idempotencyResult{
				status: entry.Status,
				body:   body,
			},
		}
	}
	c.pruneLocked(now)
	c.enforceCapLocked()
}

// snapshotForPersist marshals current entries under the lock and returns
// the serialized bytes plus the persist path. Caller must hold c.mu.
func (c *idempotencyCache) snapshotForPersist() ([]byte, string) {
	if c.persistPath == "" {
		return nil, ""
	}

	persisted := persistedIdempotencyState{
		Entries: make(map[string]persistedIdempotencyEntry),
	}
	for key, entry := range c.entries {
		if entry == nil || entry.inFlight {
			continue
		}
		persisted.Entries[key] = persistedIdempotencyEntry{
			CreatedAtUnixNano: entry.createdAt.UnixNano(),
			ReqHashHex:        hex.EncodeToString(entry.reqHash[:]),
			Status:            entry.result.status,
			BodyBase64:        base64.StdEncoding.EncodeToString(entry.result.body),
		}
	}
	data, _ := json.Marshal(persisted)
	return data, c.persistPath
}

func writePersistData(data []byte, path string) error {
	if path == "" || data == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
