package poseidon

import (
	"testing"
)

func TestMDS(t *testing.T) {
	for i:=2;i<50;i++ {
		mds,err := createMDSMatrix(i)
		if err != nil {
			t.Errorf("create mds matrices err: %s",err)
			return
		}

		mul0,err := MatMul(mds.m,mds.mInv)
		if err != nil {
			t.Errorf("mds mul err: %s",err)
			return
		}

		mul1,err := MatMul(mds.mHat,mds.mHatInv)
		if err != nil {
			t.Errorf("mds mHat mul err: %s",err)
			return
		}

		if !IsIdentity(mul0) || !IsIdentity(mul1){
			t.Error("mds m or mHat is invalid!")
		}

		mul2,err := MatMul(mds.mPrime,mds.mDoublePrime)
		if err != nil {
			t.Errorf("mds mPrime mul err: %s",err)
			return
		}

		if !IsEqual(mds.m,mul2) {
			t.Error("mds mPrime is invalid!")
			return
		}
	}
}
