package poseidon

import (
	"fmt"
)

// MdsMatrices is matrices for improving the efficiency of Poseidon hash.
// see more details in the paper https://eprint.iacr.org/2019/458.pdf page 20.
type MdsMatrices[E Element[E]] struct {
	// the input mds matrix.
	m Matrix[E]
	// mInv is the inverse of the mds matrix.
	mInv Matrix[E]
	// mHat is the matrix by eliminating the first row and column of the matrix.
	mHat Matrix[E]
	// mHatInv is the inverse of the mHat matrix.
	mHatInv Matrix[E]
	// mPrime is the matrix m' in the paper, and it holds m = m'*m''.
	// mPrime consists of:
	// 1  |  0
	// 0  |  mHat
	mPrime Matrix[E]
	// mDoublePrime is the matrix m'' in the paper, and it holds m = m'*m''.
	// mDoublePrime consists of:
	// m_00  |  V
	// w_hat |  I
	// where M_00 is the first element of the mds matrix,
	// w_hat and V are t-1 length vectors,
	// I is the (t-1)*(t-1) identity matrix.
	mDoublePrime Matrix[E]
}

// SparseMatrix is specifically one of the form of m”.
// This means its first row and column are each dense, and the interior matrix
// (minor to the element in both the row and column) is the identity.
// For simplicity, we omit the identity matrix in m”.
type SparseMatrix[E Element[E]] struct {
	// WHat is the first column of the m'' matrix, this is a little different with the WHat in the paper because
	// we add M_00 to the beginning of the WHat.
	WHat Vector[E]
	// V contains all but the first element, because it is already included in WHat.
	V Vector[E]
}

// generate the mds (cauchy) matrix, which is invertible, and
// its sub-matrices are invertible as well.
func genMDS[E Element[E]](t int) Matrix[E] {
	xVec := make([]E, t)
	yVec := make([]E, t)

regen:
	// generate x and y value where x[i] != y[i] to allow the values to be inverted, and
	// there are no duplicates in the x vector or y vector, so that
	// the determinant is always non-zero.
	for i := 0; i < t; i++ {
		xVec[i] = newElement[E]().SetUint64(uint64(i))
		yVec[i] = newElement[E]().SetUint64(uint64(i + t))
	}

	m := make([][]E, t)
	for i := 0; i < t; i++ {
		m[i] = make([]E, t)
		for j := 0; j < t; j++ {
			m[i][j] = newElement[E]().Add(xVec[i], yVec[j])
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
func deriveMatrices[E Element[E]](m Matrix[E]) (*MdsMatrices[E], error) {
	mInv, err := Invert(m)
	if err != nil {
		return nil, fmt.Errorf("gen mInv failed, err: %w", err)
	}

	mHat, err := minor(m, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("gen mHat failed, err: %w", err)
	}

	mHatInv, err := Invert(mHat)
	if err != nil {
		return nil, fmt.Errorf("gen mHatInv failed, err: %w", err)
	}

	mPrime := genPrime(m)

	mDoublePrime, err := genDoublePrime(m, mHatInv)
	if err != nil {
		return nil, fmt.Errorf("gen double prime m failed, err: %w", err)
	}

	return &MdsMatrices[E]{m, mInv, mHat, mHatInv, mPrime, mDoublePrime}, nil
}

// generate the matrix m', where m = m'*m”.
func genPrime[E Element[E]](m Matrix[E]) Matrix[E] {
	prime := make([][]E, row(m))
	prime[0] = append(prime[0], one[E]())
	for i := 1; i < column(m); i++ {
		prime[0] = append(prime[0], zero[E]())
	}

	for i := 1; i < row(m); i++ {
		prime[i] = make([]E, column(m))
		prime[i][0] = zero[E]()
		for j := 1; j < column(m); j++ {
			prime[i][j] = m[i][j]
		}
	}
	return prime
}

// generate the matrix m”, where m = m'*m”.
func genDoublePrime[E Element[E]](m, mHatInv Matrix[E]) (Matrix[E], error) {
	w, v := genPreVectors(m)

	wHat, err := LeftMatMul(mHatInv, w)
	if err != nil {
		return nil, fmt.Errorf("compute WHat failed, err: %w", err)
	}

	doublePrime := make([][]E, row(m))
	doublePrime[0] = append([]E{m[0][0]}, v...)
	for i := 1; i < row(m); i++ {
		doublePrime[i] = make([]E, column(m))
		doublePrime[i][0] = wHat[i-1]
		for j := 1; j < column(m); j++ {
			if j == i {
				doublePrime[i][j] = one[E]()
			} else {
				doublePrime[i][j] = zero[E]()
			}
		}
	}

	return doublePrime, nil
}

// generate pre-computed vectors used in the sparse matrix.
func genPreVectors[E Element[E]](m Matrix[E]) (Vector[E], Vector[E]) {
	v := make([]E, column(m)-1)
	copy(v, m[0][1:])

	w := make([]E, row(m)-1)
	for i := 1; i < row(m); i++ {
		w[i-1] = m[i][0]
	}

	return w, v
}

// parseSparseMatrix parses the sparse matrix.
func parseSparseMatrix[E Element[E]](m Matrix[E]) (*SparseMatrix[E], error) {
	sub, err := minor(m, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("get the sub matrix err: %w", err)
	}

	// m should be the sparse matrix, which has a (t-1)*(t-1) sub identity matrix.
	if !IsSquareMatrix(m) || !IsIdentity(sub) {
		return nil, fmt.Errorf("cannot parse the sparse matrix")
	}

	// WHat is the first column of the sparse matrix.
	sparse := new(SparseMatrix[E])
	sparse.WHat = make([]E, row(m))
	for i := 0; i < column(m); i++ {
		sparse.WHat[i] = m[i][0]
	}

	// V contains all but the first element.
	sparse.V = make([]E, column(m)-1)
	copy(sparse.V, m[0][1:])

	return sparse, nil
}

// generate the sparse and pre-sparse matrices for fast computation of the Poseidon hash.
// we refer to the paper https://eprint.iacr.org/2019/458.pdf page 20 and
// the implementation in https://github.com/filecoin-project/neptune.
// at each partial round, use a sparse matrix instead of a dense matrix.
// to do this, we have to factored into two components, such that m' x m” = m,
// use the sparse matrix m” as the mds matrix,
// then the previous layer's m is replaced by m x m' = m*.
// from the last partial round, do the same work to the first partial round.
func genSparseMatrix[E Element[E]](m Matrix[E], rp int) ([]*SparseMatrix[E], Matrix[E], error) {
	sparses := make([]*SparseMatrix[E], rp)

	preSparse := copyMatrixRows(m, 0, row(m))
	for i := 0; i < rp; i++ {
		mds, err := deriveMatrices(preSparse)
		if err != nil {
			return nil, nil, fmt.Errorf("derive mds matrices err: %w", err)
		}

		// m* = m x m'
		mat, err := MatMul(m, mds.mPrime)
		if err != nil {
			return nil, nil, fmt.Errorf("get the previous layer's matrix err: %w", err)
		}

		// parse the sparse matrix by reverse order.
		sparses[rp-i-1], err = parseSparseMatrix(mds.mDoublePrime)
		if err != nil {
			return nil, nil, fmt.Errorf("parse sparse matrix err: %w", err)
		}

		preSparse = copyMatrixRows(mat, 0, row(mat))
	}

	return sparses, preSparse, nil
}
