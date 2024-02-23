package poseidon

import (
	"testing"

	ff "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestCalcRoundNum(t *testing.T) {
	tests := []struct {
		t    int
		s    bool
		want struct {
			rf, rp int
		}
	}{
		{3, true, struct{ rf, rp int }{rf: 8, rp: 55}},
		{4, true, struct{ rf, rp int }{rf: 8, rp: 56}},
		{5, true, struct{ rf, rp int }{rf: 8, rp: 56}},
		{6, true, struct{ rf, rp int }{rf: 8, rp: 56}},
		{7, true, struct{ rf, rp int }{rf: 8, rp: 56}},
		{8, true, struct{ rf, rp int }{rf: 8, rp: 57}},
		{9, true, struct{ rf, rp int }{rf: 8, rp: 57}},
		{10, true, struct{ rf, rp int }{rf: 8, rp: 57}},
		{11, true, struct{ rf, rp int }{rf: 8, rp: 57}},
		{12, true, struct{ rf, rp int }{rf: 8, rp: 57}},
		{13, true, struct{ rf, rp int }{rf: 8, rp: 57}},
		{14, true, struct{ rf, rp int }{rf: 8, rp: 57}},
		{15, true, struct{ rf, rp int }{rf: 8, rp: 57}},
		{16, true, struct{ rf, rp int }{rf: 8, rp: 59}},
		{17, true, struct{ rf, rp int }{rf: 8, rp: 59}},
		{25, true, struct{ rf, rp int }{rf: 8, rp: 59}},
		{37, true, struct{ rf, rp int }{rf: 8, rp: 60}},
		{65, true, struct{ rf, rp int }{rf: 8, rp: 61}},
		{3, false, struct{ rf, rp int }{rf: 6, rp: 51}},
		{4, false, struct{ rf, rp int }{rf: 6, rp: 52}},
		{5, false, struct{ rf, rp int }{rf: 6, rp: 52}},
		{6, false, struct{ rf, rp int }{rf: 6, rp: 52}},
		{7, false, struct{ rf, rp int }{rf: 6, rp: 52}},
		{8, false, struct{ rf, rp int }{rf: 6, rp: 53}},
		{9, false, struct{ rf, rp int }{rf: 6, rp: 53}},
		{10, false, struct{ rf, rp int }{rf: 6, rp: 53}},
		{11, false, struct{ rf, rp int }{rf: 6, rp: 53}},
		{12, false, struct{ rf, rp int }{rf: 6, rp: 53}},
		{13, false, struct{ rf, rp int }{rf: 6, rp: 53}},
		{14, false, struct{ rf, rp int }{rf: 6, rp: 53}},
		{15, false, struct{ rf, rp int }{rf: 6, rp: 53}},
		{16, false, struct{ rf, rp int }{rf: 6, rp: 54}},
		{17, false, struct{ rf, rp int }{rf: 6, rp: 54}},
		{25, false, struct{ rf, rp int }{rf: 6, rp: 54}},
		{37, false, struct{ rf, rp int }{rf: 6, rp: 55}},
		{65, false, struct{ rf, rp int }{rf: 6, rp: 56}},
	}

	for _, cases := range tests {
		getRf, getRp := calcRoundNumbers[*ff.Element](cases.t, cases.s)
		assert.Equal(t, getRf, cases.want.rf)
		assert.Equal(t, getRp, cases.want.rp)
	}
}

func TestGenRoundConstants(t *testing.T) {
	tests := []struct {
		t, rf, rp int
		want      int
	}{
		{t: 8, rf: 8, rp: 55, want: 504},
		{t: 9, rf: 8, rp: 56, want: 576},
		{t: 10, rf: 8, rp: 57, want: 650},
		{t: 11, rf: 8, rp: 57, want: 715},
		{t: 12, rf: 8, rp: 57, want: 780},
	}

	for _, cases := range tests {
		get := genRoundConstants[*ff.Element](1, 1, 255, cases.t, cases.rf, cases.rp)
		assert.Equal(t, len(get), cases.want)
	}
}

func TestGenCompressedRoundConstants(t *testing.T) {
	tests := []struct {
		t, rf, rp int
		want      int
	}{
		{t: 8, rf: 8, rp: 55, want: 119},
		{t: 9, rf: 8, rp: 56, want: 128},
		{t: 10, rf: 8, rp: 57, want: 137},
		{t: 11, rf: 8, rp: 57, want: 145},
		{t: 12, rf: 8, rp: 57, want: 153},
	}

	for _, cases := range tests {
		roundContants := genRoundConstants[*ff.Element](1, 1, 255, cases.t, cases.rf, cases.rp)
		m := genMDS[*ff.Element](cases.t)
		mds, _ := deriveMatrices(m)
		comRoundContantsm, err := genCompressedRoundConstants(cases.t, cases.rf, cases.rp, roundContants, mds)
		assert.NoError(t, err)

		assert.Equal(t, len(comRoundContantsm), cases.want)
	}
}
