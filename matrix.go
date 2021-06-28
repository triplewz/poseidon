package poseidon

import (
	"github.com/pkg/errors"
	ff "github.com/triplewz/poseidon/bls12_381"
)

type Matrix [][]*ff.Element

type Vector []*ff.Element

var one = new(ff.Element).SetOne()
var zero = new(ff.Element).SetZero()

// return the column numbers of the matrix.
func column(m Matrix) int {
	if len(m) > 0 {
		length := len(m[0])
		for i := 1; i < len(m); i++ {
			if len(m[i]) != length {
				panic("m is not matrix!")
			}
		}
		return length
	} else {
		return 0
	}
}

// return the row numbers of the matrix.
func row(m Matrix) int {
	return len(m)
}

// for 0 <= i < row, 0 <= j < column, compute M_ij*scalar.
func ScalarMul(scalar *ff.Element, m Matrix) Matrix {
	res := make([][]*ff.Element, len(m))
	for i := 0; i < len(m); i++ {
		res[i] = make([]*ff.Element, len(m[i]))
		for j := 0; j < len(m[i]); j++ {
			res[i][j] = new(ff.Element).Mul(scalar, m[i][j])
		}
	}

	return res
}

// for 0 <= i < length, compute v_i*scalar.
func ScalarVecMul(scalar *ff.Element, v Vector) Vector {
	res := make([]*ff.Element, len(v))

	for i := 0; i < len(v); i++ {
		res[i] = new(ff.Element).Mul(scalar, v[i])
	}

	return res
}

func VecAdd(a, b Vector) (Vector, error) {
	if len(a) != len(b) {
		return nil, errors.New("length err: cannot compute vector add!")
	}

	res := make([]*ff.Element, len(a))
	for i := 0; i < len(a); i++ {
		res[i] = new(ff.Element).Add(a[i], b[i])
	}

	return res, nil
}

func VecSub(a, b Vector) (Vector, error) {
	if len(a) != len(b) {
		return nil, errors.New("length err: cannot compute vector sub!")
	}

	res := make([]*ff.Element, len(a))
	for i := 0; i < len(a); i++ {
		res[i] = new(ff.Element).Sub(a[i], b[i])
	}

	return res, nil
}

// compute the product between two vectors.
func VecMul(a, b Vector) (*ff.Element, error) {
	if len(a) != len(b) {
		return nil, errors.New("length err: cannot compute vector mul!")
	}

	res := new(ff.Element)
	for i := 0; i < len(a); i++ {
		tmp := new(ff.Element).Mul(a[i], b[i])
		res.Add(res, tmp)
	}

	return res, nil
}

func IsVecEqual(a, b Vector) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i].Cmp(b[i]) != 0 {
			return false
		}
	}

	// time-constant comparison, against timing attacks.
	//res := 0
	//for i := 0; i < len(a); i++ {
	//	res |= a[i].Cmp(b[i])
	//}
	//return res == 0

	return true
}

// if delta(m)≠0, m is invertible.
// so we can transform m to the upper triangular matrix,
// and if all upper diagonal elements are not zero, then m is invertible.
func IsInvertible(m Matrix) bool {
	// need to copy m.
	tmp := copyMatrixRows(m, 0, row(m))
	if !IsSquareMatrix(tmp) {
		return false
	}

	shadow := MakeIdentity(row(tmp))
	upper, _, err := upperTriangular(tmp, shadow)
	if err != nil {
		panic(err)
	}

	for i := 0; i < row(tmp); i++ {
		if upper[i][i].Cmp(zero) == 0 {
			return false
		}
	}

	return true
}

// compute the product between two matrices.
func MatMul(a, b Matrix) (Matrix, error) {
	if row(a) != column(b) {
		return nil, errors.New("cannot compute the result!")
	}

	transb := transpose(b)

	var err error
	res := make([][]*ff.Element, row(a))
	for i := 0; i < row(a); i++ {
		res[i] = make([]*ff.Element, column(b))
		for j := 0; j < column(b); j++ {
			res[i][j], err = VecMul(a[i], transb[j])
			if err != nil {
				return nil, errors.Errorf("vec mul err: %s", err)
			}
		}
	}

	return res, nil
}

// left Matrix multiplication, denote by M*V, where M is the matrix, and V is the vector.
func LeftMatMul(m Matrix, v Vector) (Vector, error) {
	if !IsSquareMatrix(m) {
		panic("matrix is not square!")
	}

	if row(m) != len(v) {
		return nil, errors.New("length err: cannot compute matrix multiplication with the vector!")
	}

	res := make([]*ff.Element, len(v))
	var err error
	for i := 0; i < len(v); i++ {
		res[i], err = VecMul(m[i], v)
		if err != nil {
			return nil, errors.Errorf("vector mul err:%s", err)
		}
	}

	return res, nil
}

// right Matrix multiplication, denote by V*M, where V is the vector, and M is the matrix.
func RightMatMul(v Vector, m Matrix) (Vector, error) {
	if !IsSquareMatrix(m) {
		return nil, errors.New("matrix is not square!")
	}

	if row(m) != len(v) {
		return nil, errors.New("length err: cannot compute matrix multiplication with the vector!")
	}

	transm := transpose(m)
	res := make([]*ff.Element, len(v))
	var err error
	for i := 0; i < len(v); i++ {
		res[i], err = VecMul(transm[i], v)
		if err != nil {
			return nil, errors.Errorf("vector mul err:%s", err)
		}
	}

	return res, nil
}

// swap rows and columns of the matrix.
func transpose(m Matrix) Matrix {
	res := make([][]*ff.Element, column(m))

	for j := 0; j < column(m); j++ {
		res[j] = make([]*ff.Element, len(m))
		for i := 0; i < len(m); i++ {
			res[j][i] = m[i][j]
		}
	}

	return res
}

// the square matrix is a t*t matrix.
func IsSquareMatrix(m Matrix) bool {
	return row(m) == column(m)
}

// make t*t identity matrix.
func MakeIdentity(t int) Matrix {
	res := make([][]*ff.Element, t)

	for i := 0; i < t; i++ {
		res[i] = make([]*ff.Element, t)
		for j := 0; j < t; j++ {
			if i == j {
				res[i][j] = one
			} else {
				res[i][j] = zero
			}
		}
	}

	return res
}

// determine if a matrix is identity.
func IsIdentity(m Matrix) bool {
	for i := 0; i < row(m); i++ {
		for j := 0; j < column(m); j++ {
			if ((i == j) && m[i][j].Cmp(one) != 0) || ((i != j) && (m[i][j].Cmp(zero) != 0)) {
				return false
			}
		}
	}

	return true
}

func IsEqual(a, b Matrix) bool {
	if row(a) != row(b) || column(a) != column(b) {
		return false
	}

	for i := 0; i < row(a); i++ {
		for j := 0; j < column(a); j++ {
			if a[i][j].Cmp(b[i][j]) != 0 {
				return false
			}
		}
	}

	// time-constant comparison, against timing attacks.
	//res := 0
	//for i := 0; i < row(a); i++ {
	//	for j := 0; j < column(a); j++ {
	//		res |= a[i][j].Cmp(b[i][j])
	//	}
	//}
	//return res == 0

	return true
}

// remove i-th row and j-th column of the matrix.
func minor(m Matrix, rowIndex, columnIndex int) (Matrix, error) {
	if !IsSquareMatrix(m) {
		return nil, errors.New("matrix is not square!")
	}

	res := make([][]*ff.Element, row(m)-1)

	for i := 0; i < row(m); i++ {
		if i < rowIndex {
			for j := 0; j < column(m); j++ {
				if j != columnIndex {
					res[i] = append(res[i], m[i][j])
				}
			}
		} else if i > rowIndex {
			for j := 0; j < column(m); j++ {
				if j != columnIndex {
					res[i-1] = append(res[i-1], m[i][j])
				}
			}
		}
	}

	return res, nil
}

// determine if the first k elements are zero.
func isFirstKZero(v Vector, k int) bool {
	if k == 0 && v[0].Cmp(zero) == 0 {
		return false
	}

	for i := 0; i < k; i++ {
		if v[i].Cmp(zero) != 0 {
			return false
		}
	}
	return true
}

// find the first non-zero element in the given column.
func findNonZero(m Matrix, index int) (pivot *ff.Element, pivotIndex int, err error) {
	pivotIndex = -1

	if index > column(m) {
		return nil, -1, errors.New("index out of range!")
	}

	for i := 0; i < row(m); i++ {
		if m[i][index].Cmp(zero) != 0 {
			pivot = m[i][index]
			pivotIndex = i
			break
		}
	}

	return
}

// assume matrix is partially reduced to upper triangular.
func eliminate(m, shadow Matrix, columnIndex int) (Matrix, Matrix, error) {
	pivot, pivotIndex, err := findNonZero(m, columnIndex)
	if err != nil || pivotIndex == -1 {
		return nil, nil, errors.Errorf("cannot find non-zero element: %s", err)
	}

	pivotInv := new(ff.Element).Inverse(pivot)

	for i := 0; i < row(m); i++ {
		if i == pivotIndex {
			continue
		}

		if m[i][columnIndex].Cmp(zero) != 0 {
			factor := new(ff.Element).Mul(m[i][columnIndex], pivotInv)

			scalarPivot := ScalarVecMul(factor, m[pivotIndex])

			m[i], err = VecSub(m[i], scalarPivot)
			if err != nil {
				return nil, nil, errors.Errorf("matrix m eliminate failed, vec sub err: %s", err)
			}

			shadowPivot := shadow[pivotIndex]

			scalarShadowPivot := ScalarVecMul(factor, shadowPivot)

			shadow[i], err = VecSub(shadow[i], scalarShadowPivot)
			if err != nil {
				return nil, nil, errors.Errorf("matrix shadow eliminate failed, vec sub err: %s", err)
			}
		}
	}

	return m, shadow, nil
}

// copy rows between start index and end index.
func copyMatrixRows(m Matrix, startIndex, endIndex int) Matrix {
	if startIndex >= endIndex {
		panic("start index should be less than end index!")
	}

	res := make([][]*ff.Element, endIndex-startIndex)

	for i := 0; i < endIndex-startIndex; i++ {
		res[i] = make([]*ff.Element, column(m))
		copy(res[i], m[i+startIndex])
	}

	return res
}

// reverse rows of the matrix.
func reverseRows(m Matrix) Matrix {
	res := make([][]*ff.Element, row(m))

	for i := 0; i < row(m); i++ {
		res[i] = make([]*ff.Element, column(m))
		copy(res[i], m[row(m)-i-1])
	}

	return res
}

// determine if numbers of zero elements equals to n.
func zeroNums(v Vector, n int) bool {
	count := 0
	for i := 0; i < len(v); i++ {
		if v[i].Cmp(zero) != 0 {
			break
		}
		count++
	}

	if count == n {
		return true
	}

	return false
}

// determine if a matrix is upper triangular.
func isUpperTriangular(m Matrix) bool {
	for i := 0; i < row(m); i++ {
		if !zeroNums(m[i], i) {
			return false
		}
	}

	return true
}

// transform a square matrix to upper triangular matrix.
func upperTriangular(m, shadow Matrix) (Matrix, Matrix, error) {
	if !IsSquareMatrix(m) {
		return nil, nil, errors.New("matrix is not square!")
	}

	curr := copyMatrixRows(m, 0, row(m))
	currShadow := copyMatrixRows(shadow, 0, row(shadow))
	result := make([][]*ff.Element, row(m))
	shadowResult := make([][]*ff.Element, row(shadow))
	c := 0
	var err error
	for row(curr) > 1 {
		result[c] = make([]*ff.Element, column(m))
		shadowResult[c] = make([]*ff.Element, column(shadow))
		curr, currShadow, err = eliminate(curr, currShadow, c)
		if err != nil {
			return nil, nil, errors.Errorf("matrix eliminate err: %s", err)
		}

		copy(result[c], curr[0])
		copy(shadowResult[c], currShadow[0])

		c++

		curr = copyMatrixRows(curr, 1, row(curr))
		currShadow = copyMatrixRows(currShadow, 1, row(currShadow))
	}
	result[c] = make([]*ff.Element, column(m))
	shadowResult[c] = make([]*ff.Element, column(shadow))
	copy(result[c], curr[0])
	copy(shadowResult[c], currShadow[0])

	return result, shadowResult, nil
}

// reduce a upper triangular matrix to identity matrix.
func reduceToIdentity(m, shadow Matrix) (Matrix, Matrix, error) {
	var err error

	result := make([][]*ff.Element, row(m))
	shadowResult := make([][]*ff.Element, row(shadow))
	for i := 0; i < row(m); i++ {
		result[i] = make([]*ff.Element, column(m))
		shadowResult[i] = make([]*ff.Element, column(shadow))
		indexi := row(m) - i - 1

		factor := m[indexi][indexi]
		if factor.Cmp(zero) == 0 {
			return nil, nil, errors.New("cannot compute the result!")
		}

		factorInv := new(ff.Element).Inverse(factor)

		norm := ScalarVecMul(factorInv, m[indexi])

		shadowNorm := ScalarVecMul(factorInv, shadow[indexi])

		for j := 0; j < i; j++ {
			indexj := row(m) - j - 1
			val := norm[indexj]

			scalarVal := ScalarVecMul(val, result[j])
			scalarShadow := ScalarVecMul(val, shadowResult[j])

			norm, err = VecSub(norm, scalarVal)
			if err != nil {
				return nil, nil, errors.Errorf("reduces to identity matrix failed, err: %s", err)
			}

			shadowNorm, err = VecSub(shadowNorm, scalarShadow)
			if err != nil {
				return nil, nil, errors.Errorf("reduces to identity matrix failed, err: %s", err)
			}
		}
		copy(result[i], norm)
		copy(shadowResult[i], shadowNorm)
	}

	result = reverseRows(result)
	shadowResult = reverseRows(shadowResult)

	return result, shadowResult, nil
}

// use Gaussian elimination to invert a matrix.
// A|I -> I|A^-1.
func Invert(m Matrix) (Matrix, error) {
	if !IsInvertible(m) {
		return nil, errors.Errorf("the matrix is not invertible!")
	}

	shadow := MakeIdentity(row(m))

	up, upShadow, err := upperTriangular(m, shadow)
	if err != nil {
		return nil, errors.Errorf("transform to upper triangular matrix failed, err: %s", err)
	}

	if !isUpperTriangular(up) {
		return nil, errors.Errorf("the matrix should be upper triangular before reducing!")
	}

	// reduce m to identity, so shadow matrix transforms to the inverse of m.
	reduce, reducedShadow, err := reduceToIdentity(up, upShadow)
	if err != nil {
		return nil, errors.Errorf("reduce to identity failed, err: %s", err)
	}

	if !IsIdentity(reduce) {
		return nil, errors.New("reduces failed, the result is not the identity matrix!")
	}

	return reducedShadow, nil
}
