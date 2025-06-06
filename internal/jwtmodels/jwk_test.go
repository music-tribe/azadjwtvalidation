package jwtmodels

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateJwkKid(t *testing.T) {
	t.Run("expect success and valid kid", func(t *testing.T) {
		b, err := base64.RawURLEncoding.DecodeString("AQAB")
		require.NoError(t, err)
		number, err := base64.RawURLEncoding.DecodeString("5AyZN4Z3bcKQxeGucjBeQHPpGKcy5o1t7gYF6hrPa_9-X6xcpxaZHc2fiWjP0nc5j9aNIeTKE-Eiq0S40v6Swpm0M3yp2niArIcpVRGCdS7fNOIcezdRyZHAylHK6T1CbuJU1pgg5ujGhYi2KnCgESI1x_Vvl6FlmeJNAMVk44OOfhmr4CYx9Kq5AY1Lh5qP5C3dMGXmGalvtuvchD90D8xlFAUWiv11WFcacDedWBz6VPkshzDB4x5jDyPLQJp9Ynx1cDQh4uRlA7-pLVPA4SRIWdBiRCDa-wYfhHJI0yn3Nsq3mGxpJ05LdFKi71bESFVtVEjEQW5-zpr7Lsqa8Q")
		require.NoError(t, err)
		rsaPub := rsa.PublicKey{
			N: new(big.Int).SetBytes(number),
			E: int(new(big.Int).SetBytes(b).Uint64()),
		}

		kid, err := GenerateJwkKid(&rsaPub)
		assert.NoError(t, err)
		assert.Equal(t, "0bxzOoXqygO5AKM2rmZn1DQafGQCUJG8fdeiyJYCvbY", kid)
	})
}
