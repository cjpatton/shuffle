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

// TODO(cjpatton) implement the general k-shuffle.
// TODO(cjpatton) Modify Mix() to also output the shared secrets.

package shuffle

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// Decrypts the sequence of ElGamal ciphertexts {(R[i], C[i])}, applies the
// specified permutation, and outputs the resulting sequence.
func (sk *SecretKey) Mix(R, C []*big.Int, perm []int) ([]*big.Int, error) {
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

// ILMPProve implements the prover role in the interactive proof for ILMP. It
// takes as input the log of each element of the public sequences X and Y.
//
// Communication is implemented using a Go channel. As such, it should be very
// easy to overlay this code on a network connection.
func (params *KeyParameters) ILMPProve(x, y []big.Int, msg chan []big.Int) error {
	if len(x) != len(y) {
		msg <- nil
		return errors.New("input lengths do not match")
	}

	// P1
	N := len(x)
	theta := make([]big.Int, N+1)
	for i := 1; i < N; i++ {
		t, err := params.Sample()
		if err != nil {
			msg <- nil
			return err
		}
		theta[i] = *t
	}

	A := make([]big.Int, N)
	var X, Y big.Int
	for i := 0; i < N; i++ {
		X.Mul(&x[i], &theta[i])
		X.Exp(params.G, &X, params.P)
		Y.Mul(&y[i], &theta[i+1])
		Y.Exp(params.G, &Y, params.P)
		A[i].Mul(&X, &Y)
		A[i].Mod(&A[i], params.P)
	}
	msg <- A

	// V1
	gamma := <-msg
	if gamma == nil {
		return errors.New("channel closed by peer (V1)")
	}

	// P2
	r := make([]big.Int, N-1)
	num := new(big.Int).SetUint64(1)
	den := new(big.Int).SetUint64(1)

	var z, q, inv big.Int
	for i := N - 2; i >= 0; i-- {
		num.Mul(num, &y[i+1])
		den.Mul(den, &x[i+1])
		z.GCD(&inv, &q, den, params.Q)
		r[i].Mul(num, &inv)
		r[i].Mul(&r[i], &gamma[0])
		r[i].Mod(&r[i], params.Q)
		if (N-i-1)%2 == 1 {
			r[i].Sub(params.Q, &r[i])
		}
		r[i].Add(&r[i], &theta[i+1])
	}
	msg <- r

	return nil
}

// ILMPVerify implements the verifier role in the interactive proof for ILMP.
// It takes as input the public sequences X and Y.
func (params *KeyParameters) ILMPVerify(X, Y []big.Int, msg chan []big.Int) (bool, error) {
	var err error

	if len(X) != len(Y) {
		msg <- nil
		return false, errors.New("input lengths do not match")
	}
	N := len(X)

	// P1
	A := <-msg
	if A == nil {
		return false, errors.New("channel closed by peer (P1)")
	}

	// V1
	gamma := make([]big.Int, 1)
	t, err := params.Sample()
	if err != nil {
		msg <- nil
		return false, err
	}
	gamma[0] = *t
	msg <- gamma

	// P2
	r := <-msg
	if r == nil {
		return false, errors.New("channel closed by peer (P2)")
	}

	var L, R big.Int
	// V2
	//
	// First equation
	var qMinusGamma big.Int
	qMinusGamma.Sub(params.Q, &gamma[0])
	L.Exp(&Y[0], &r[0], params.P)
	if (N-1)%2 == 1 {
		R.Exp(&X[0], &qMinusGamma, params.P)
	} else {
		R.Exp(&X[0], &gamma[0], params.P)
	}
	R.Mul(&A[0], &R)
	R.Mod(&R, params.P)
	if L.Cmp(&R) != 0 {
		return false, nil
	}

	// Intermediate equations
	for i := 1; i < N-1; i++ {
		L.Exp(&X[i], &r[i-1], params.P)
		R.Exp(&Y[i], &r[i], params.P)
		L.Mul(&L, &R)
		L.Mod(&L, params.P)
		if L.Cmp(&A[i]) != 0 {
			return false, nil
		}
	}

	// Last equation
	L.Exp(&X[N-1], &r[N-2], params.P)
	R.Exp(&Y[N-1], &qMinusGamma, params.P)
	R.Mul(&A[N-1], &R)
	R.Mod(&R, params.P)
	if L.Cmp(&R) != 0 {
		return false, nil
	}
	return true, nil
}

// Shuffle0Prove implements the prover role for the interactive proof of
// Shuffle0 (the simple k-shuffle).
func (params *KeyParameters) Shuffle0Prove(x, y []big.Int, c, d *big.Int, msg chan []big.Int) error {
	if len(x) != len(y) {
		msg <- nil
		return errors.New("input lengths do not match")
	}
	N := len(x)

	// V1
	gamma := <-msg
	if gamma == nil {
		return errors.New("channel closed by peer (V1)")
	}
	t := &gamma[0]

	// P1
	phi := make([]big.Int, 2*N)
	psi := make([]big.Int, 2*N)
	dt := new(big.Int).Mul(d, t)
	ct := new(big.Int).Mul(c, t)

	for i := 0; i < N; i++ {
		phi[i].Sub(&x[i], dt)
		phi[i].Mod(&phi[i], params.Q)
		phi[N+i] = *c
		psi[i].Sub(&y[i], ct)
		psi[i].Mod(&psi[i], params.Q)
		psi[N+i] = *d
	}

	if err := params.ILMPProve(phi, psi, msg); err != nil {
		return errors.New(fmt.Sprintf("ilmp: %v", err))
	}

	return nil
}

// Shuffle0Verify implements the verifier role in the interactive proof of
// Shuffle0 (the simple k-shuffle).
func (params *KeyParameters) Shuffle0Verify(X, Y []big.Int, C, D *big.Int, msg chan []big.Int) (bool, error) {

	if len(X) != len(Y) {
		msg <- nil
		return false, errors.New("input lengths do not match")
	}
	N := len(X)

	// V1
	t, err := params.Sample()
	if err != nil {
		msg <- nil
		return false, err
	}
	gamma := make([]big.Int, 1)
	gamma[0] = *t
	msg <- gamma

	// P1
	U := new(big.Int).Exp(D, t, params.P)
	W := new(big.Int).Exp(C, t, params.P)
	var Uinv, Winv, Q, Z big.Int
	Z.GCD(&Uinv, &Q, U, params.P)
	Z.GCD(&Winv, &Q, W, params.P)

	Phi := make([]big.Int, 2*N)
	Psi := make([]big.Int, 2*N)
	for i := 0; i < N; i++ {
		Phi[i].Mul(&X[i], &Uinv)
		Phi[i].Mod(&Phi[i], params.P)
		Phi[N+i] = *C
		Psi[i].Mul(&Y[i], &Winv)
		Psi[i].Mod(&Psi[i], params.P)
		Psi[N+i] = *D
	}

	if ok, err := params.ILMPVerify(Phi, Psi, msg); err != nil {
		return false, errors.New(fmt.Sprintf("ilmp: %s", err))
	} else if !ok {
		return false, nil
	}

	return true, nil
}

func (sk *SecretKey) ShuffleProve(X, Y []big.Int, msg chan []big.Int) error {
	if len(X) != len(Y) {
		msg <- nil
		return errors.New("input lengths do not match")
	}
	n := len(X)

	// P1
	e := make([][]big.Int, 2)
	E := make([][]big.Int, 2)
	for i := 0; i < 2; i++ {
		e[i] = make([]big.Int, n)
		E[i] = make([]big.Int, n)
		for j := 0; j < n; j++ {
			t, err := sk.Sample()
			if err != nil {
				msg <- nil
				return err
			}
			e[i][j] = *t
			E[i][j].Exp(sk.G, t, sk.P)
		}
	}
	d, err := sk.Sample()
	if err != nil {
		msg <- nil
		return err
	}
	D := new(big.Int)
	D.Exp(sk.G, d, sk.P)

	out1 := make([]big.Int, 2*n+1)
	copy(out1, E[0])
	copy(out1[n:], E[1])
	out1[2*n] = *D
	msg <- out1

	// V1
	v1 := <-msg
	if v1 == nil || len(v1) != 2*n {
		return errors.New("malformed V1")
	}
	return nil
}

func (pk *PublicKey) ShuffleVerify(X, Y []big.Int, msg chan []big.Int) (bool, error) {
	if len(X) != len(Y) {
		msg <- nil
		return false, errors.New("input lengths do not match")
	}
	n := len(X)

	// P1
	p1 := <-msg
	if p1 == nil || len(p1) != 2*n+1 {
		msg <- nil
		return false, errors.New("malformed P1")
	}

	// V2
	f := make([][]big.Int, 2)
	for i := 0; i < 2; i++ {
		f[i] = make([]big.Int, n)
		for j := 0; j < n; j++ {
			t, err := pk.Sample()
			if err != nil {
				msg <- nil
				return false, err
			}
			f[i][j] = *t
		}
	}
	v1 := make([]big.Int, 2*n)
	copy(v1, f[0])
	copy(v1[n:], f[1])
	msg <- v1

	return false, nil
}
