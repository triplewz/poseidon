package poseidon

import (
	"github.com/pkg/errors"
	ff "github.com/triplewz/poseidon/bls12_381"
)

// mdsMatrices is matrices for improving the efficiency of Poseidon hash.
// see more details in the paper https://eprint.iacr.org/2019/458.pdf page 20.
type mdsMatrices struct {
	// the input mds matrix.
	m Matrix
	// mInv is the inverse of the mds matrix.
	mInv Matrix
	// mHat is the matrix by eliminating the first row and column of the matrix.
	mHat Matrix
	// mHatInv is the inverse of the mHat matrix.
	mHatInv Matrix
	// mPrime is the matrix m' in the paper, and it holds m = m'*m''.
	// mPrime consists of:
	// 1  |  0
	// 0  |  mHat
	mPrime Matrix
	// mDoublePrime is the matrix m'' in the paper, and it holds m = m'*m''.
	// mDoublePrime consists of:
	// m_00  |  v
	// w_hat |  I
	// where M_00 is the first element of the mds matrix,
	// w_hat and v are t-1 length vectors,
	// I is the (t-1)*(t-1) identity matrix.
	mDoublePrime Matrix
}

// SparseMatrix is specifically one of the form of m''.
// This means its first row and column are each dense, and the interior matrix
// (minor to the element in both the row and column) is the identity.
// For simplicity, we omit the identity matrix in m''.
type SparseMatrix struct {
	// wHat is the first column of the M'' matrix, this is a little different with the wHat in the paper because
	// we add M_00 to the beginning of the wHat.
	wHat Vector
	// v contains all but the first element, because it is already included in wHat.
	v Vector
}

// create the mds matrices.
func createMDSMatrix(t int) (*mdsMatrices, error) {
	m := genMDS(t)

	return deriveMatrices(m)
}

// generate the mds (cauchy) matrix, which is invertible, and
// its sub-matrices are invertible as well.
func genMDS(t int) Matrix {
	xVec := make([]*ff.Element, t)
	yVec := make([]*ff.Element, t)

regen:
	// generate x and y value where x[i] != y[i] to allow the values to be inverted, and
	// there are no duplicates in the x vector or y vector, so that
	// the determinant is always non-zero.
	for i := 0; i < t; i++ {
		xVec[i] = new(ff.Element).SetUint64(uint64(i))
		yVec[i] = new(ff.Element).SetUint64(uint64(i + t))
	}

	m := make([][]*ff.Element, t)
	for i := 0; i < t; i++ {
		m[i] = make([]*ff.Element, t)
		for j := 0; j < t; j++ {
			m[i][j] = new(ff.Element).Add(xVec[i], yVec[j])
			m[i][j].Inverse(m[i][j])
		}
	}

	// m must be invertible.
	if !IsInvertible(m) {
		t++
		goto regen
	}

	// m must be symmetric.
	transm := transpose(m)
	if !IsEqual(transm, m) {
		panic("m is not symmetric!")
	}

	return m
}

// derive the mds matrices from m.
func deriveMatrices(m Matrix) (*mdsMatrices, error) {
	mInv, err := Invert(m)
	if err != nil {
		return nil, errors.Errorf("gen mInv failed, err: %s", err)
	}

	mHat, err := minor(m, 0, 0)
	if err != nil {
		return nil, errors.Errorf("gen mHat failed, err: %s", err)
	}

	mHatInv, err := Invert(mHat)
	if err != nil {
		return nil, errors.Errorf("gen mHatInv failed, err: %s", err)
	}

	mPrime := genPrime(m)

	mDoublePrime, err := genDoublePrime(m, mHatInv)
	if err != nil {
		return nil, errors.Errorf("gen double prime m failed, err: %s", err)
	}

	return &mdsMatrices{m, mInv, mHat, mHatInv, mPrime, mDoublePrime}, nil
}

// generate the matrix m', where m = m'*m''.
func genPrime(m Matrix) Matrix {
	prime := make([][]*ff.Element, row(m))
	prime[0] = append(prime[0], one)
	for i := 1; i < column(m); i++ {
		prime[0] = append(prime[0], zero)
	}

	for i := 1; i < row(m); i++ {
		prime[i] = make([]*ff.Element, column(m))
		prime[i][0] = zero
		for j := 1; j < column(m); j++ {
			prime[i][j] = m[i][j]
		}
	}
	return prime
}

// generate the matrix m'', where m = m'*m''.
func genDoublePrime(m, mHatInv Matrix) (Matrix, error) {
	w, v := genPreVectors(m)

	wHat, err := LeftMatMul(mHatInv, w)
	if err != nil {
		return nil, errors.Errorf("compute wHat failed, err: %s", err)
	}

	doublePrime := make([][]*ff.Element, row(m))
	doublePrime[0] = append([]*ff.Element{m[0][0]}, v...)
	for i := 1; i < row(m); i++ {
		doublePrime[i] = make([]*ff.Element, column(m))
		doublePrime[i][0] = wHat[i-1]
		for j := 1; j < column(m); j++ {
			if j == i {
				doublePrime[i][j] = one
			} else {
				doublePrime[i][j] = zero
			}
		}
	}

	return doublePrime, nil
}

// generate pre-computed vectors used in the sparse matrix.
func genPreVectors(m Matrix) (Vector, Vector) {
	v := make([]*ff.Element, column(m)-1)
	copy(v, m[0][1:])

	w := make([]*ff.Element, row(m)-1)
	for i := 1; i < row(m); i++ {
		w[i-1] = m[i][0]
	}

	return w, v
}

// parseSparseMatrix parses the sparse matrix.
func parseSparseMatrix(m Matrix) (*SparseMatrix, error) {
	sub, err := minor(m, 0, 0)
	if err != nil {
		return nil, errors.Errorf("get the sub matrix err: %s", err)
	}

	// m should be the sparse matrix, which has a (t-1)*(t-1) sub identity matrix.
	if !IsSquareMatrix(m) || !IsIdentity(sub) {
		return nil, errors.Errorf("cannot parse the sparse matrix!")
	}

	// wHat is the first column of the sparse matrix.
	sparse := new(SparseMatrix)
	sparse.wHat = make([]*ff.Element, row(m))
	for i := 0; i < column(m); i++ {
		sparse.wHat[i] = m[i][0]
	}

	// v contains all but the first element.
	sparse.v = make([]*ff.Element, column(m)-1)
	copy(sparse.v, m[0][1:])

	return sparse, nil
}

// generate the sparse and pre-sparse matrices for fast computation of the Poseidon hash.
// we refer to the paper https://eprint.iacr.org/2019/458.pdf page 20 and
// the implementation in https://github.com/filecoin-project/neptune.
// at each partial round, use a sparse matrix instead of a dense matrix.
// to do this, we have to factored into two components, such that m' x m'' = m,
// use the sparse matrix m'' as the mds matrix,
// then the previous layer's m is replaced by m x m' = m*.
// from the last partial round, do the same work to the first partial round.
func genSparseMatrix(m Matrix, rp int) ([]*SparseMatrix, Matrix, error) {
	sparses := make([]*SparseMatrix, rp)

	preSparse := copyMatrixRows(m, 0, row(m))
	for i := 0; i < rp; i++ {
		mds, err := deriveMatrices(preSparse)
		if err != nil {
			return nil, nil, errors.Errorf("derive mds matrices err: %s", err)
		}

		// m* = m x m'
		mat, err := MatMul(m, mds.mPrime)
		if err != nil {
			return nil, nil, errors.Errorf("get the previous layer's matrix err: %s", err)
		}

		// parse the sparse matrix by reverse order.
		sparses[rp-i-1], err = parseSparseMatrix(mds.mDoublePrime)
		if err != nil {
			return nil, nil, errors.Errorf("parse sparse matrix err: %s", err)
		}

		preSparse = copyMatrixRows(mat, 0, row(mat))
	}

	return sparses, preSparse, nil
}
