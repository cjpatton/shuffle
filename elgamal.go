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
	"errors"
	"math/big"
)

// KeyParameters stores the public parameters for Diffie-Hellman or ElGamal
// encryption. These are a generator G and primes P and Q such that Q divides
// (P-1) and G^Q is congruent to 1 mod P; that is, <G> is a cyclic subgroup of
// Z/p of order Q.
type KeyParameters struct {
	P, G, Q   *big.Int
	qMinusOne *big.Int
	one       *big.Int
}

// MaxMsgBytes returns the maximum number of message that may be encrypted
// under the modulus P.
func (params *KeyParameters) MaxMsgBytes() int {
	return (params.P.BitLen() / 8) - 4
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
	params.one = new(big.Int)
	params.one.SetUint64(1)
	params.qMinusOne = new(big.Int)
	params.qMinusOne.Sub(params.Q, params.one)
	return params
}

// PublicKey stores the public key Y = G^X for Diffie-Hellman or ElGamal.
type PublicKey struct {
	KeyParameters
	Y *big.Int
}

// SecretKey stores the secret key X \in [1..Q-1] for Diffie_hellman or ElGamal.
type SecretKey struct {
	KeyParameters
	qMinusX *big.Int
	X       *big.Int
}

// GenerateKeys chooses a random exponent and returns a secret/public key pair.
func (params *KeyParameters) GenerateKeys() (pk *PublicKey, sk *SecretKey) {
	var err error
	sk = new(SecretKey)
	pk = new(PublicKey)
	sk.KeyParameters = *params
	pk.KeyParameters = *params

	// Choose a random secret key X.
	sk.P = params.P
	sk.G = params.G
	sk.Q = params.Q
	// Choose a random exponent in [0,Q-1).
	if sk.X, err = pk.KeyParameters.Sample(); err != nil {
		return nil, nil
	}
	sk.qMinusX = new(big.Int)
	sk.qMinusX.Sub(params.Q, sk.X)

	// Compute Y = G^X mod P.
	pk.P = params.P
	pk.G = params.G
	pk.Q = params.Q
	pk.Y = new(big.Int)
	pk.Y.Exp(params.G, sk.X, params.P)
	return
}

// Sample samples a random value from [1..q-1.]
func (params *KeyParameters) Sample() (*big.Int, error) {
	// Choose a random exponent in [0,Q-1).
	R, err := rand.Int(rand.Reader, params.qMinusOne)
	if err != nil {
		return nil, err
	}
	// Add 1 so that the exponent is in [1,Q-1].
	R.Add(R, params.one)
	return R, nil
}

// Encrypt takes as input a plaintext (presumably an element of Z/p)
// and outputs an ElGamal ciphertext (a tuple over Z/p).
func (pk *PublicKey) Encrypt(M *big.Int) (R *big.Int, C *big.Int) {
	var err error
	C = new(big.Int)

	R, err = pk.Sample()
	if err != nil {
		return nil, nil
	}

	C.Exp(pk.Y, R, pk.P)
	C.Mul(M, C)
	C.Mod(C, pk.P)
	R.Exp(pk.G, R, pk.P)
	return
}

// Decrypt takes as input an ElGamal ciphertext (presumably a tuple over Z/p)
// and outputs the corresponding plaintext element of Z/p.
func (sk *SecretKey) Decrypt(R, C *big.Int) (M *big.Int) {
	M = new(big.Int)
	M.Exp(R, sk.qMinusX, sk.P)
	M.Mul(M, C)
	M.Mod(M, sk.P)
	return
}

// Encode takes as input a slice of bytes and outputs the corresponding
// element of Z/p.
func (params *KeyParameters) Encode(msg []byte) (*big.Int, error) {
	M := new(big.Int)
	maxMsgBytes := params.MaxMsgBytes()
	if len(msg) > maxMsgBytes {
		return nil, errors.New("message too big")
	}
	paddedMsg := make([]byte, maxMsgBytes+2)
	paddedMsg[0] = 0xFF
	bytes := copy(paddedMsg[1:], msg)
	paddedMsg[bytes+1] = 0xFF
	M.SetBytes(paddedMsg)
	return M, nil
}

// Decode takes as input an element of Z/p and outputs the corresponding
// message.
func (params *KeyParameters) Decode(M *big.Int) ([]byte, error) {
	paddedMsg := M.Bytes()
	i := len(paddedMsg) - 1
	for ; i >= 0; i-- {
		if paddedMsg[i] != 0x00 {
			break
		}
	}
	msg := make([]byte, i-1)
	copy(msg, paddedMsg[1:])
	return msg, nil
}
