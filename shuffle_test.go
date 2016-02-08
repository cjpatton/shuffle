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
	"testing"
)

// Public parameters for testing encryption keys. This is the NIST 2048-bit
// MODP group with a 256-bit prime order subgroup from RFC5114. One should
// generate his/her own parameters in light of the logjam attack. (See
// https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf for details.)
const testP = "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2" +
	"5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30" +
	"16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD" +
	"5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B" +
	"6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C" +
	"4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E" +
	"F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9" +
	"67E144E5140564251CCACB83E6B486F6B3CA3F7971506026" +
	"C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3" +
	"75F26375D7014103A4B54330C198AF126116D2276E11715F" +
	"693877FAD7EF09CADB094AE91E1A1597"

const testG = "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF2054" +
	"07F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555" +
	"BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18" +
	"A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B" +
	"777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83" +
	"1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55" +
	"A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14" +
	"C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915" +
	"B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6" +
	"184B523D1DB246C32F63078490F00EF8D647D148D4795451" +
	"5E2327CFEF98C582664B4C0F6CC41659"

const testQ = "8CF83642A709A097B447997640129DA299B1A47D1EB3750B" +
	"A308B0FE64F5FBD3"

func TestNewKeyParametersFromString(t *testing.T) {
	var ntrials int = 10
	params := NewKeyParametersFromStrings(testP, testG, testQ)
	if params == nil {
		t.Fatal("NewKeyParamatersFromStrings(testP, testG, testQ) = nil")
	}
	if !params.P.ProbablyPrime(ntrials) {
		t.Fatal("primality test fails for P")
	}
	if !params.Q.ProbablyPrime(ntrials) {
		t.Fatal("primality test fails for Q")
	}
}

func TestGenerateKeys(t *testing.T) {
	params := NewKeyParametersFromStrings(testP, testG, testQ)
	sk, pk := GenerateKeys(params)
	if sk == nil {
		t.Fatal("sk, pk := GenerateKeys(params); sk = nil")
	}
	if pk == nil {
		t.Fatal("sk, pk := GenerateKeys(params); pk = nil")
	}
	t.Log("secret key: %s", sk.X)
	t.Log("public key: %s", pk.Y)
	Y := new(big.Int)
	Y.Exp(params.G, sk.X, params.P)
	if pk.Y.Cmp(Y) != 0 {
		t.Fatal("sk, pk := GenerateKeys(params); G^X != Y")
	}
}
