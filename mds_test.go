package poseidon

import (
	"testing"

	ff "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestMDS(t *testing.T) {
	for i := 2; i < 50; i++ {
		m := genMDS[*ff.Element](i)
		mds, err := deriveMatrices(m)
		assert.NoError(t, err)

		mul0, err := MatMul(mds.m, mds.mInv)
		assert.NoError(t, err)

		mul1, err := MatMul(mds.mHat, mds.mHatInv)
		assert.NoError(t, err)

		if !IsIdentity(mul0) || !IsIdentity(mul1) {
			t.Error("mds m or mHat is invalid!")
		}

		mul2, err := MatMul(mds.mPrime, mds.mDoublePrime)
		assert.NoError(t, err)
		assert.Equal(t, mds.m, mul2)
	}
}
