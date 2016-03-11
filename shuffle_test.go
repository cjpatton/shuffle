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

// Test the ILMP protocol on various batch sizes.
func TestSILMPP(t *testing.T) {
	params := NewKeyParametersFromStrings(testP, testG, testQ)
	for N := 2; N < 10; N++ {
		x := make([]big.Int, N)
		y := make([]big.Int, N)

		for i := 0; i < N; i++ {
			x[i].SetInt64(int64(i) + 2)
			y[i].SetInt64(int64(i) + 2)
		}

		//c, _ := params.Sample()
		c := new(big.Int).SetUint64(2)
		x[0].Add(&x[0], c)
		y[N-1].Add(&y[N-1], c)

		X := make([]big.Int, N)
		Y := make([]big.Int, N)
		for i := 0; i < N; i++ {
			X[i].Exp(params.G, &x[i], params.P)
			Y[i].Exp(params.G, &y[i], params.P)
		}

		msg := make(chan []big.Int)

		go func() {
			if err := params.ILMPProve(x, y, msg); err != nil {
				t.Errorf("%d: prover: %s", N, err)
			}
		}()

		if ok, err := params.ILMPVerify(X, Y, msg); err != nil {
			t.Errorf("%d: verifier:", N, err)
		} else if !ok {
			t.Errorf("%d: failed to verify", N)
		}
	}
}

// Test the ILMP protocol on a more realistic input.
func TestSILMPP2(t *testing.T) {
	params := NewKeyParametersFromStrings(testP, testG, testQ)

	N := 10
	x := make([]big.Int, N)
	y := make([]big.Int, N)

	for i := 0; i < N; i++ {
		x[i].SetInt64(int64(i) + 2)
		y[i].SetInt64(int64(i) + 2)
	}

	c, _ := params.Sample()
	d, _ := params.Sample()
	e, _ := params.Sample()
	f, _ := params.Sample()
	g, _ := params.Sample()
	h, _ := params.Sample()
	x[0].Mul(&x[0], c)
	x[7].Mul(&x[7], d)
	x[2].Mul(&x[2], e)
	x[0].Mul(&x[0], f)
	x[0].Mul(&x[0], g)
	x[3].Mul(&x[3], h)
	y[1].Mul(&y[1], c)
	y[9].Mul(&y[9], d)
	y[2].Mul(&y[2], e)
	y[5].Mul(&y[5], f)
	y[8].Mul(&y[8], g)
	y[8].Mul(&y[8], h)

	X := make([]big.Int, N)
	Y := make([]big.Int, N)
	for i := 0; i < N; i++ {
		X[i].Exp(params.G, &x[i], params.P)
		Y[i].Exp(params.G, &y[i], params.P)
	}

	msg := make(chan []big.Int)

	go func() {
		if err := params.ILMPProve(x, y, msg); err != nil {
			t.Errorf("%d: prover: %s", N, err)
		}
	}()

	if ok, err := params.ILMPVerify(X, Y, msg); err != nil {
		t.Errorf("%d: verifier:", N, err)
	} else if !ok {
		t.Errorf("%d: failed to verify", N)
	}
}

// Test the ILMP protocol on a mal-formed input.
func TestBadSILMPP(t *testing.T) {
	params := NewKeyParametersFromStrings(testP, testG, testQ)

	N := 10
	x := make([]big.Int, N)
	y := make([]big.Int, N)

	for i := 0; i < N; i++ {
		x[i].SetInt64(int64(i) + 2)
		y[i].SetInt64(int64(i) + 2)
	}

	// This input is mal-formed because g^{x_1, ..., x_n} != g^{y_1, ..., y_n}.
	c, _ := params.Sample()
	d, _ := params.Sample()
	e, _ := params.Sample()
	f, _ := params.Sample()
	x[0].Mul(&x[0], c)
	x[7].Mul(&x[7], d)
	x[2].Mul(&x[2], e)
	x[0].Mul(&x[0], f)
	y[9].Mul(&y[9], d)
	y[2].Mul(&y[2], e)
	y[5].Mul(&y[5], f)

	X := make([]big.Int, N)
	Y := make([]big.Int, N)
	for i := 0; i < N; i++ {
		X[i].Exp(params.G, &x[i], params.P)
		Y[i].Exp(params.G, &y[i], params.P)
	}

	msg := make(chan []big.Int)

	go func() {
		if err := params.ILMPProve(x, y, msg); err != nil {
			t.Errorf("%d: prover: %s", N, err)
		}
	}()

	if ok, err := params.ILMPVerify(X, Y, msg); err != nil {
		t.Errorf("%d: verifier:", N, err)
	} else if ok {
		t.Errorf("%d: verification passed: expected failure", N)
	}
}

func TestShuffle0ProveVerify(t *testing.T) {
	params := NewKeyParametersFromStrings(testP, testG, testQ)

	//c, _ := params.Sample()
	c := new(big.Int).SetUint64(33)
	d := new(big.Int).SetUint64(2)
	C := new(big.Int).Exp(params.G, c, params.P)
	D := new(big.Int).Exp(params.G, d, params.P)

	N := 3
	x := make([]big.Int, N)
	y := make([]big.Int, N)
	for i := 0; i < N; i++ {
		x[i].SetInt64(23)
		y[i].Mul(&x[i], c)
		x[i].Mul(&x[i], d)
	}

	X := make([]big.Int, N)
	Y := make([]big.Int, N)
	for i := 0; i < N; i++ {
		X[i].Exp(params.G, &x[i], params.P)
		Y[i].Exp(params.G, &y[i], params.P)
	}

	msg := make(chan []big.Int)

	go func() {
		if err := params.Shuffle0Prove(x, y, c, d, msg); err != nil {
			t.Errorf("prover: %s", err)
		}
	}()

	if ok, err := params.Shuffle0Verify(X, Y, C, D, msg); err != nil {
		t.Errorf("verifier: %s", err)
	} else if !ok {
		t.Errorf("failed to verify", N)
	}
}
