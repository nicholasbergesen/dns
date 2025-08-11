package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nicholasbergesen/dns/dns"
)

func TestCacheConcurrency(t *testing.T) {
	// Reset cache for test
	cacheMutex.Lock()
	cache = make(map[string]dns.Message, 10000)
	cacheMutex.Unlock()

	// Create a test message
	testMsg := dns.Message{
		Header: dns.Header{ID: 1234},
	}

	// Test concurrent access to cache
	var wg sync.WaitGroup
	numRoutines := 10
	numOperations := 100

	// Start multiple goroutines performing cache operations
	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "test.com"
				
				// Mix of get, set, and delete operations
				switch j % 3 {
				case 0:
					setCacheEntry(key, testMsg)
				case 1:
					getCacheEntry(key)
				case 2:
					deleteCacheEntry(key)
				}
			}
		}(i)
	}

	// Wait for all operations to complete
	wg.Wait()
	
	// If we get here without a race condition panic, the test passes
	t.Log("Cache concurrency test completed successfully")
}

func TestMessageIsExpiredFix(t *testing.T) {
	// Test message with no answers should be expired
	msgNoAnswers := dns.Message{
		Answers: []dns.ResourceRecord{},
	}
	if !msgNoAnswers.IsExpired() {
		t.Error("Message with no answers should be expired")
	}

	// Test message with answers in the past should be expired
	pastTime := time.Now().Add(-1 * time.Hour)
	msgExpired := dns.Message{
		Answers: []dns.ResourceRecord{
			{
				TTL:          3600, // 1 hour TTL
				CreationDate: pastTime.Add(-2 * time.Hour), // Created 3 hours ago
			},
		},
	}
	if !msgExpired.IsExpired() {
		t.Error("Message with expired answers should be expired")
	}

	// Test message with valid answers should not be expired
	msgValid := dns.Message{
		Answers: []dns.ResourceRecord{
			{
				TTL:          3600, // 1 hour TTL
				CreationDate: time.Now(), // Created now
			},
		},
	}
	if msgValid.IsExpired() {
		t.Error("Message with valid answers should not be expired")
	}
}

func TestIsBlockedConcurrency(t *testing.T) {
	// Reset blocked list for test
	blockedMutex.Lock()
	blocked = []string{"blocked.com", "evil.com", "spam.net"}
	blockedMutex.Unlock()

	var wg sync.WaitGroup
	numRoutines := 10

	// Test concurrent access to blocked list
	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				// Test various domains
				domains := []string{"blocked.com", "evil.com", "good.com", "example.com"}
				for _, domain := range domains {
					isBlocked(domain)
				}
			}
		}()
	}

	wg.Wait()
	t.Log("Blocked list concurrency test completed successfully")
}

func TestCacheSizeLimit(t *testing.T) {
	// Reset cache for test
	cacheMutex.Lock()
	cache = make(map[string]dns.Message, 10000)
	cacheMutex.Unlock()

	// Fill cache beyond limit
	testMsg := dns.Message{Header: dns.Header{ID: 1234}}
	
	// Add more entries than MAX_CACHE_SIZE to test eviction
	for i := 0; i < MAX_CACHE_SIZE + 100; i++ {
		key := fmt.Sprintf("test%d.com", i)
		setCacheEntry(key, testMsg)
	}

	// Check cache size is within limits
	cacheMutex.RLock()
	cacheSize := len(cache)
	cacheMutex.RUnlock()

	if cacheSize > MAX_CACHE_SIZE {
		t.Errorf("Cache size %d exceeds maximum %d", cacheSize, MAX_CACHE_SIZE)
	}

	t.Logf("Cache size after overflow test: %d", cacheSize)
}