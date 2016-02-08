// Copyright (c) 2016, Christopher Patton. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package shuffle

import (
	"crypto/rand"
	"math/big"
)

// KeyParameters stores the public parameters for Diffie-Hellman or ElGamal
// encryption. These are a generator G and primes P and Q such that Q divides
// (P-1), and G^Q is congruent to 1 mod P; that is, <G> is a cyclic group of
// order Q.
type KeyParameters struct {
	P, G, Q *big.Int
}

// NewKeyParametersFromStrings creates a KeyParamters object from strings
// encoding the parameters in hexadecimal.
func NewKeyParametersFromStrings(p, g, q string) *KeyParameters {
	params := new(KeyParameters)
	params.P = new(big.Int)
	params.G = new(big.Int)
	params.Q = new(big.Int)
	if _, ok := params.P.SetString(p, 16); !ok {
		return nil
	}
	if _, ok := params.G.SetString(g, 16); !ok {
		return nil
	}
	if _, ok := params.Q.SetString(q, 16); !ok {
		return nil
	}
	return params
}

// SecretKey stores the secret key X \in [1..Q-1] for Diffie_hellman or ElGamal.
type SecretKey struct {
	KeyParameters
	X *big.Int
}

// PublicKey stores the public key Y = G^X for Diffie-Hellman or ElGamal.
type PublicKey struct {
	KeyParameters
	Y *big.Int
}

// GenerateKeys chooses a random exponent and returns a secret/public key pair.
func GenerateKeys(params *KeyParameters) (sk *SecretKey, pk *PublicKey) {
	skMax := new(big.Int)
	one := new(big.Int)
	one.SetUint64(1)
	skMax.Set(params.Q)
	skMax.Sub(skMax, one)

	var err error
	sk = new(SecretKey)
	sk.P = params.P
	sk.G = params.G
	sk.Q = params.Q
	// Choose a random X in [0,Q-1).
	if sk.X, err = rand.Int(rand.Reader, skMax); err != nil {
		return nil, nil
	}
	// Add 1 so that X is in [1,Q-1].
	sk.X.Add(sk.X, one)
	pk = new(PublicKey)
	pk.P = params.P
	pk.G = params.G
	pk.Q = params.Q
	pk.Y = new(big.Int)
	pk.Y.Exp(params.G, sk.X, params.P)
	return
}
