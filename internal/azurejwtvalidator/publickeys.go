package azurejwtvalidator

import (
	"crypto/rsa"
	"sync"
)

// Concurrency-safe map for storing public keys.
// This is used to store the public keys retrieved from the JWKs URL or passed in the config.
// It allows concurrent read and write operations, ensuring thread safety.
// The map is indexed by the key ID (kid) of the public key, which is used to identify the key in JWT validation.
// The public keys are of type *rsa.PublicKey, which is the standard type for RSA public keys in Go.
type PublicKeys struct {
	mu   sync.RWMutex
	data map[string]*rsa.PublicKey
}

func NewPublicKeys() *PublicKeys {
	return &PublicKeys{
		data: make(map[string]*rsa.PublicKey),
	}
}

func NewPublicKeysWithData(data map[string]*rsa.PublicKey) *PublicKeys {
	copied := make(map[string]*rsa.PublicKey, len(data))
	// We can't use maps.Copy here as it requires Go 1.21+ and generics which isn't supported in Traefik plugins yet (due to Yaegi).
	for k, v := range data {
		copied[k] = v
	}
	return &PublicKeys{
		data: copied,
	}
}

func (cs *PublicKeys) Get(k string) (val *rsa.PublicKey, ok bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	val, ok = cs.data[k]
	return
}

func (cs *PublicKeys) Set(k string, val *rsa.PublicKey) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.data[k] = val
}

func (cs *PublicKeys) Write(newMap map[string]*rsa.PublicKey) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if newMap == nil {
		cs.data = make(map[string]*rsa.PublicKey)
		return
	}
	cloned := make(map[string]*rsa.PublicKey, len(newMap))
	// We can't use maps.Copy here as it requires Go 1.21+ and generics which isn't supported in Traefik plugins yet (due to Yaegi).
	for k, v := range newMap {
		cloned[k] = v
	}
	cs.data = cloned
}

func (cs *PublicKeys) Len() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.data)
}
