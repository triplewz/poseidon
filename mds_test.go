package poseidon

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMDS(t *testing.T) {
	for i:=2;i<50;i++ {
		mds,err := createMDSMatrix(i)
		assert.Equal(t, err,nil)

		mul0,err := MatMul(mds.m,mds.mInv)
		assert.Equal(t, err,nil)

		mul1,err := MatMul(mds.mHat,mds.mHatInv)
		assert.Equal(t, err,nil)

		if !IsIdentity(mul0) || !IsIdentity(mul1){
			t.Error("mds m or mHat is invalid!")
		}

		mul2,err := MatMul(mds.mPrime,mds.mDoublePrime)
		assert.Equal(t, err,nil)
		assert.Equal(t, mds.m,mul2)
	}
}
