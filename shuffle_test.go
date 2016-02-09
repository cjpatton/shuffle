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
	"math/big"
	"strconv"
	"testing"
)

func TestShuffle(t *testing.T) {
	params := NewKeyParametersFromStrings(testP, testG, testQ)
	pk, sk := params.GenerateKeys()

	n := 10
	R := make([]*big.Int, n)
	C := make([]*big.Int, n)

	for i := 0; i < n; i++ {
		msg := []byte(strconv.Itoa(i + 1))
		X, err := pk.KeyParameters.Encode(msg)
		if err != nil {
			t.Fatal("X, err := pk.KeyParameters.Encode(msg); err:", err)
		}
		R[i], C[i] = pk.Encrypt(X)
	}

	perm := GeneratePerm(n)
	t.Log(perm)
	M, err := sk.Shuffle(R, C, perm)
	if err != nil {
		t.Fatal("M, err := Shuffle(R, C, perm); err:", err)
	}

	for i := range M {
		if msg, err := pk.KeyParameters.Decode(M[i]); err != nil {
			t.Fatalf("msg, err := pk.KeyParameters.Decode(M[%d]); err: %s",
				i, err)
		} else {
			t.Logf("%d: %s", i, msg)
		}
	}
}
