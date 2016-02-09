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
	"fmt"
	"math/big"
)

// Decrypts the sequence of ElGamal ciphertexts {(R[i], C[i])}, applies the
// specified permutation, and outputs the resulting sequence.
func (sk *SecretKey) Shuffle(R, C []*big.Int, perm []int) ([]*big.Int, error) {
	if len(R) != len(C) {
		return nil, errors.New(fmt.Sprintf(
			"sequence length mismatch: |R|=%d, |C|=%d", len(R), len(C)))
	}

	M := make([]*big.Int, len(R))
	for i := 0; i < len(R); i++ {
		if j := perm[i]; M[j] == nil && 0 <= j && j < len(R) {
			M[j] = sk.Decrypt(R[i], C[i])
		} else {
			return nil, errors.New("parameter is not a permutation")
		}
	}
	return M, nil
}

// GeneratePerm generates a pseudo-random permutation on n-vectors using the
// Knuth (Fisher-Yates) shuffle.
func GeneratePerm(n int) []int {
	perm := make([]int, n)
	for i := 0; i < n; i++ {
		perm[i] = i
	}
	one := new(big.Int)
	one.SetUint64(1)
	max := new(big.Int)
	max.SetUint64(uint64(n))
	for i := n - 1; i >= 1; i-- {
		max.Sub(max, one)
		r, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil
		}
		j := r.Uint64()
		perm[i] ^= perm[j]
		perm[j] ^= perm[i]
		perm[i] ^= perm[j]
	}
	return perm
}
