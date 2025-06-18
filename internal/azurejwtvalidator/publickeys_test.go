package azurejwtvalidator

import (
	"crypto/rsa"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPublicKeys(t *testing.T) {
	t.Run("expected non-nil PublicKeys", func(t *testing.T) {
		pk := NewPublicKeys()
		assert.NotNil(t, pk, "expected non-nil PublicKeys, got nil")
		assert.NotNil(t, pk.data, "expected non-nil data map, got nil")
		assert.Empty(t, pk.data, "expected empty data map, got length %d", len(pk.data))
	})
}

func TestNewPublicKeysWithData(t *testing.T) {
	t.Run("expected PublicKeys with provided data", func(t *testing.T) {
		data := map[string]*rsa.PublicKey{
			"key1": {},
			"key2": {},
		}
		pk := NewPublicKeysWithData(data)
		assert.NotNil(t, pk, "expected non-nil PublicKeys, got nil")
		assert.Equal(t, data, pk.data, "expected data map to match provided data")
	})

	t.Run("modifying input map after NewPublicKeysWithData causes race", func(t *testing.T) {
		data := map[string]*rsa.PublicKey{
			"key1": {},
		}
		pk := NewPublicKeysWithData(data)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			// Simulate concurrent read
			for range 10 {
				_, _ = pk.Get("key1")
			}
		}()

		go func() {
			defer wg.Done()
			// Simulate external modification of the original map
			for i := range 1000 {
				data[fmt.Sprintf("key%d", i+2)] = &rsa.PublicKey{}
			}
		}()

		wg.Wait()
	})
}

func TestPublicKeys_GetSet(t *testing.T) {
	t.Run("existing key", func(t *testing.T) {
		pk := NewPublicKeys()
		key := &rsa.PublicKey{}
		pk.Set("key1", key)

		val, ok := pk.Get("key1")
		assert.True(t, ok, "expected key to exist, got false")
		assert.Equal(t, key, val, "expected retrieved key to match set key")
	})

	t.Run("non-existing key", func(t *testing.T) {
		pk := NewPublicKeys()
		val, ok := pk.Get("non-existing")
		assert.False(t, ok, "expected key to not exist, got true")
		assert.Nil(t, val, "expected nil value for non-existing key")
	})

	t.Run("concurrent access", func(t *testing.T) {
		pk := NewPublicKeys()
		key := &rsa.PublicKey{}
		pk.Set("key1", key)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			val, ok := pk.Get("key1")
			assert.True(t, ok, "expected key to exist in goroutine")
			assert.Equal(t, key, val, "expected retrieved key to match set key in goroutine")
		}()

		go func() {
			defer wg.Done()
			for i := range 5 {
				keyn := &rsa.PublicKey{}
				pk.Set(fmt.Sprintf("key%d", i), keyn)
			}
		}()

		wg.Wait()
	})
}

func TestPublicKeys_Write(t *testing.T) {
	t.Run("write new data", func(t *testing.T) {
		pk := NewPublicKeys()
		newMap := map[string]*rsa.PublicKey{
			"key1": {},
			"key2": {},
		}
		pk.Write(newMap)
		assert.Equal(t, 2, pk.Len(), "expected 2 keys after write")
	})

	t.Run("concurrent access", func(t *testing.T) {
		pk := NewPublicKeys()
		key := &rsa.PublicKey{}
		pk.Set("key1", key)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			val, ok := pk.Get("key1")
			assert.True(t, ok, "expected key to exist in goroutine")
			assert.Equal(t, key, val, "expected retrieved key to match set key in goroutine")
		}()

		go func() {
			defer wg.Done()
			for range 5 {
				newMap := map[string]*rsa.PublicKey{
					"key1": {},
					"key2": {},
				}
				pk.Write(newMap)
			}
		}()

		wg.Wait()
	})

	t.Run("modifying newMap after Write does not affect internal map", func(t *testing.T) {
		origMap := map[string]*rsa.PublicKey{
			"key1": {},
		}
		pk := NewPublicKeys()
		pk.Write(origMap)

		// Modify origMap after Write
		origMap["key2"] = &rsa.PublicKey{}

		// Internal map should not be affected
		assert.Equal(t, 1, pk.Len(), "expected internal map to remain unchanged after modifying input map")
		_, ok := pk.Get("key2")
		assert.False(t, ok, "expected key2 to not exist in internal map")
	})

	t.Run("concurrent modification of newMap after Write", func(t *testing.T) {
		origMap := map[string]*rsa.PublicKey{
			"key1": {},
		}
		pk := NewPublicKeys()
		pk.Write(origMap)

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			for i := range 10 {
				origMap[fmt.Sprintf("key%d", i+2)] = &rsa.PublicKey{}
			}
		}()

		go func() {
			defer wg.Done()
			for range 10 {
				_, _ = pk.Get("key1")
			}
		}()

		wg.Wait()
		// Internal map should still only have the original key
		assert.Equal(t, 1, pk.Len(), "expected internal map to remain unchanged after concurrent modification of input map")
	})

	t.Run("Write with nil map replaces internal map with nil", func(t *testing.T) {
		pk := NewPublicKeys()
		pk.Set("key1", &rsa.PublicKey{})
		pk.Write(nil)
		assert.Equal(t, 0, pk.Len(), "expected length 0 after writing nil map")
	})
}

func TestPublicKeys_Len(t *testing.T) {
	t.Run("length of empty map", func(t *testing.T) {
		pk := NewPublicKeys()
		assert.Equal(t, 0, pk.Len(), "expected length 0 for empty map")
	})

	t.Run("length of non-empty map", func(t *testing.T) {
		pk := NewPublicKeys()
		pk.Set("key1", &rsa.PublicKey{})
		pk.Set("key2", &rsa.PublicKey{})
		assert.Equal(t, 2, pk.Len(), "expected length 2 for non-empty map")
	})
}
