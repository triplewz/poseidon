package poseidon

import (
	ff "github.com/triplewz/poseidon/bls12_381"
	"testing"
)

var two = new(ff.Element).SetUint64(2)
var three = new(ff.Element).SetUint64(3)
var four = new(ff.Element).SetUint64(4)
var five = new(ff.Element).SetUint64(5)
var six = new(ff.Element).SetUint64(6)
var seven = new(ff.Element).SetUint64(7)
var eight = new(ff.Element).SetUint64(8)
var nine = new(ff.Element).SetUint64(9)

func TestVector(t *testing.T) {
	negTwo := new(ff.Element).Neg(two)

	sub := []struct {
		v1, v2 Vector
		want   Vector
	}{
		{Vector{one, two}, Vector{one, two}, Vector{zero, zero}},
		{Vector{one, two}, Vector{zero, zero}, Vector{one, two}},
		{Vector{three, four}, Vector{one, two}, Vector{two, two}},
		{Vector{one, two}, Vector{three, four}, Vector{negTwo, negTwo}},
	}

	for _, cases := range sub {
		get, err := VecSub(cases.v1, cases.v2)
		if err != nil {
			t.Errorf("vec sub failed, err: %s", err)
			return
		}

		if !IsVecEqual(get, cases.want) {
			t.Errorf("invalid vec sub, get: %v, want: %v", get, cases.want)
			return
		}
	}

	add := []struct {
		v1, v2 Vector
		want   Vector
	}{
		{Vector{one, two}, Vector{one, two}, Vector{two, four}},
		{Vector{one, two}, Vector{zero, zero}, Vector{one, two}},
		{Vector{one, two}, Vector{one, negTwo}, Vector{two, zero}},
	}

	for _, cases := range add {
		get, err := VecAdd(cases.v1, cases.v2)
		if err != nil {
			t.Errorf("vec add failed, err: %s", err)
			return
		}

		if !IsVecEqual(get, cases.want) {
			t.Errorf("invalid vec add, get: %v, want: %v", get, cases.want)
			return
		}
	}

	scalarmul := []struct {
		scalar *ff.Element
		v      Vector
		want   Vector
	}{
		{zero, Vector{one, two}, Vector{zero, zero}},
		{one, Vector{one, two}, Vector{one, two}},
		{two, Vector{one, two}, Vector{two, four}},
	}

	for _, cases := range scalarmul {
		get := ScalarVecMul(cases.scalar, cases.v)

		if !IsVecEqual(get, cases.want) {
			t.Errorf("invalid vec add, get: %v, want: %v", get, cases.want)
			return
		}
	}

	vecmul := []struct {
		v1, v2 Vector
		want   *ff.Element
	}{
		{Vector{one, two}, Vector{one, two}, five},
		{Vector{one, two}, Vector{zero, zero}, zero},
		{Vector{one, two}, Vector{negTwo, one}, zero},
	}

	for _, cases := range vecmul {
		get, err := VecMul(cases.v1, cases.v2)
		if err != nil {
			t.Errorf("vec mul failed, err: %s", err)
			return
		}

		if get.Cmp(cases.want) != 0 {
			t.Errorf("invalid vec mul, get: %v, want: %v", get, cases.want)
			return
		}
	}
}

func TestMatrixScalarMul(t *testing.T) {
	scalarmul := []struct {
		scalar *ff.Element
		m      Matrix
		want   Matrix
	}{
		{zero, Matrix{{one, two}, {one, two}}, Matrix{{zero, zero}, {zero, zero}}},
		{one, Matrix{{one, two}, {one, two}}, Matrix{{one, two}, {one, two}}},
		{two, Matrix{{one, two}, {three, four}}, Matrix{{two, four}, {six, eight}}},
	}

	for _, cases := range scalarmul {
		get := ScalarMul(cases.scalar, cases.m)

		if !IsEqual(get, cases.want) {
			t.Errorf("scalar mul err, get: %v, want: %v", get, cases.want)
			return
		}
	}
}

func TestIdentity(t *testing.T) {
	get := MakeIdentity(3)

	want := Matrix{{one, zero, zero}, {zero, one, zero}, {zero, zero, one}}

	if !IsEqual(get, want) {
		t.Errorf("make identity matrix err: get %v, want: %v", get, want)
	}
}

func TestMinor(t *testing.T) {
	m := Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}

	testMatrix := []struct {
		i, j int
		want Matrix
	}{
		{0, 0, Matrix{{five, six}, {eight, nine}}},
		{0, 1, Matrix{{four, six}, {seven, nine}}},
		{0, 2, Matrix{{four, five}, {seven, eight}}},
		{1, 0, Matrix{{two, three}, {eight, nine}}},
		{1, 1, Matrix{{one, three}, {seven, nine}}},
		{1, 2, Matrix{{one, two}, {seven, eight}}},
		{2, 0, Matrix{{two, three}, {five, six}}},
		{2, 1, Matrix{{one, three}, {four, six}}},
		{2, 2, Matrix{{one, two}, {four, five}}},
	}

	for _, cases := range testMatrix {
		get, err := minor(m, cases.i, cases.j)
		if err != nil {
			t.Errorf("minor err: %s", err)
			return
		}
		if !IsEqual(get, cases.want) {
			t.Errorf("invalid minor, get: %v, want: %v", get, cases.want)
			return
		}
	}
}

func TestCopyMatrix(t *testing.T) {
	m := Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}

	testMatrix := []struct {
		start, end int
		want       Matrix
	}{
		{0, 1, Matrix{{one, two, three}}},
		{0, 2, Matrix{{one, two, three}, {four, five, six}}},
		{0, 3, Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}},
		{1, 2, Matrix{{four, five, six}}},
		{1, 3, Matrix{{four, five, six}, {seven, eight, nine}}},
		{2, 3, Matrix{{seven, eight, nine}}},
	}

	for _, cases := range testMatrix {
		get := copyMatrixRows(m, cases.start, cases.end)
		if !IsEqual(get, cases.want) {
			t.Errorf("copy matrix err, get: %v, want: %v", get, cases.want)
			return
		}
	}
}

func TestTranspose(t *testing.T) {
	testMatrix := []struct {
		input, want Matrix
	}{
		{Matrix{{one, two}, {three, four}}, Matrix{{one, three}, {two, four}}},
		{Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}, Matrix{{one, four, seven}, {two, five, eight}, {three, six, nine}}},
	}

	for _, cases := range testMatrix {
		get := transpose(cases.input)

		if !IsEqual(get, cases.want) {
			t.Errorf("transpose err, get: %v, want: %v", get, cases.want)
			return
		}
	}
}

func TestUpperTriangular(t *testing.T) {
	shadow := MakeIdentity(3)
	testMatrix := []struct {
		m, s Matrix
		want bool
	}{
		{Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}, shadow, true},
		{Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}, shadow, false},
		{Matrix{{one, two, three}, {zero, three, four}, {zero, zero, three}}, shadow, true},
		{Matrix{{two, three, four}, {zero, two, four}, {zero, zero, one}}, shadow, true},
	}

	for _, cases := range testMatrix {
		m, _, err := upperTriangular(cases.m, cases.s)
		if err != nil {
			t.Errorf("upper triangular err: %s", err)
			return
		}

		get := isUpperTriangular(m)

		if get != cases.want {
			t.Errorf("make upper triangular failed, get: %v, want: %v", get, cases.want)
			return
		}

	}
}

func TestFindNonZero(t *testing.T) {
	vectorSet := []struct {
		k    int
		v    Vector
		want bool
	}{
		{0, Vector{zero, one, two, three}, false},
		{1, Vector{zero, one, two, three}, true},
		{2, Vector{zero, one, two, three}, false},
		{2, Vector{zero, zero, zero, one}, true},
		{3, Vector{zero, zero, zero, one}, true},
		{3, Vector{zero, one, two, three}, false},
		{4, Vector{zero, one, two, three}, false},
	}

	for _, cases := range vectorSet {
		get := isFirstKZero(cases.v, cases.k)

		if get != cases.want {
			t.Errorf("failed to find first k-zero elements, k:%d, get: %v, want: %v", cases.k, get, cases.want)
			return
		}
	}

	nonzeroSet := []struct {
		m    Matrix
		c    int
		want struct {
			e     *ff.Element
			index int
		}
	}{
		{Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}, 0, struct {
			e     *ff.Element
			index int
		}{two, 0}},
		{Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}, 1, struct {
			e     *ff.Element
			index int
		}{three, 0}},
		{Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}, 2, struct {
			e     *ff.Element
			index int
		}{four, 0}},
		{Matrix{{one, zero, zero}, {two, three, zero}, {four, five, zero}}, 0, struct {
			e     *ff.Element
			index int
		}{one, 0}},
		{Matrix{{one, zero, zero}, {two, three, zero}, {four, five, zero}}, 1, struct {
			e     *ff.Element
			index int
		}{three, 1}},
		{Matrix{{one, zero, zero}, {two, three, zero}, {four, five, zero}}, 2, struct {
			e     *ff.Element
			index int
		}{nil, -1}},
	}

	for _, cases := range nonzeroSet {
		gete, geti, err := findNonZero(cases.m, cases.c)
		if err != nil {
			t.Errorf("findNonZero err: %s", err)
			return
		}
		if gete != nil && cases.want.e != nil {
			if gete.Cmp(cases.want.e) != 0 || geti != cases.want.index {
				t.Errorf("find non zero failed, get element: %v, want element: %v, get index: %d, want index: %d", gete, cases.want.e, geti, cases.want.index)
				return
			}
		} else if gete == nil && cases.want.e == nil {
			if geti != cases.want.index || geti != -1 {
				t.Errorf("find non zero failed, get element: %v, want element: %v, get index: %d, want index: %d", gete, cases.want.e, geti, cases.want.index)
				return
			}
		} else {
			t.Errorf("find non zero failed, get element: %v, want element: %v, get index: %d, want index: %d", gete, cases.want.e, geti, cases.want.index)
			return
		}
	}
}

func TestMatMul(t *testing.T) {
	// [[1,2,3],[4,5,6],[7,8,9]]*[[2,3,4],[4,5,6],[7,8,8]]
	// =[[31,37,40],[70,85,95],[109,133,148]]
	m00 := new(ff.Element).SetUint64(31)
	m01 := new(ff.Element).SetUint64(37)
	m02 := new(ff.Element).SetUint64(40)
	m10 := new(ff.Element).SetUint64(70)
	m11 := new(ff.Element).SetUint64(85)
	m12 := new(ff.Element).SetUint64(94)
	m20 := new(ff.Element).SetUint64(109)
	m21 := new(ff.Element).SetUint64(133)
	m22 := new(ff.Element).SetUint64(148)

	thirteen := new(ff.Element).SetUint64(13)
	sixteen := new(ff.Element).SetUint64(16)
	eighteen := new(ff.Element).SetUint64(18)

	testMatrix := []struct {
		m1, m2 Matrix
		want   Matrix
	}{
		{Matrix{{zero, zero}, {zero, zero}}, Matrix{{one, two}, {one, two}}, Matrix{{zero, zero}, {zero, zero}}},
		{Matrix{{one, two}, {two, three}}, Matrix{{one, two}, {one, zero}}, Matrix{{three, two}, {five, four}}},
		{Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}, Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}, Matrix{{m00, m01, m02}, {m10, m11, m12}, {m20, m21, m22}}},
		{Matrix{{one, one, one}, {one, one, one}, {one, one, one}}, Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}, Matrix{{thirteen, sixteen, eighteen}, {thirteen, sixteen, eighteen}, {thirteen, sixteen, eighteen}}},
		{Matrix{{zero, zero, zero}, {zero, zero, zero}, {zero, zero, zero}}, Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}, Matrix{{zero, zero, zero}, {zero, zero, zero}, {zero, zero, zero}}},
		{Matrix{{one, zero, zero}, {zero, one, zero}, {zero, zero, one}}, Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}, Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}},
	}

	for _, cases := range testMatrix {
		get, err := MatMul(cases.m1, cases.m2)
		if err != nil {
			t.Errorf("matrix multiplication failed,err: %s", err)
			return
		}

		if !IsEqual(get, cases.want) {
			t.Errorf("matrix multiplication err, get: %v, want: %v", get, cases.want)
		}
	}

	// [[1,2,3],[4,5,6],[7,8,9]]*[1,1,1]
	// =[6,15,24]
	fifteen := new(ff.Element).SetUint64(15)
	twentyfour := new(ff.Element).SetUint64(24)

	testLeftMul := []struct {
		m    Matrix
		v    Vector
		want Vector
	}{
		{Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}, Vector{zero, zero, zero}, Vector{zero, zero, zero}},
		{Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}, Vector{one, zero, zero}, Vector{one, four, seven}},
		{Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}, Vector{one, one, one}, Vector{six, fifteen, twentyfour}},
	}

	for _, cases := range testLeftMul {
		get, err := LeftMatMul(cases.m, cases.v)
		if err != nil {
			t.Errorf("left matrix multyplicatiopn failed, err: %s", err)
			return
		}

		if !IsVecEqual(get, cases.want) {
			t.Errorf("left matrix multyplicatiopn err, get: %v, want: %v", get, cases.want)
			return
		}
	}

	// [1,1,1]*[[1,2,3],[4,5,6],[7,8,9]]
	// =[12,15,18]
	twelve := new(ff.Element).SetUint64(12)

	testRightMul := []struct {
		v    Vector
		m    Matrix
		want Vector
	}{
		{Vector{zero, zero, zero}, Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}, Vector{zero, zero, zero}},
		{Vector{one, zero, zero}, Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}, Vector{one, two, three}},
		{Vector{one, one, one}, Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}, Vector{twelve, fifteen, eighteen}},
	}

	for _, cases := range testRightMul {
		get, err := RightMatMul(cases.v, cases.m)
		if err != nil {
			t.Errorf("right matrix multyplicatiopn failed, err: %s", err)
			return
		}

		if !IsVecEqual(get, cases.want) {
			t.Errorf("right matrix multyplicatiopn err, get: %v, want: %v", get, cases.want)
			return
		}
	}
}

func TestEliminate(t *testing.T) {
	m := Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}
	shadow := MakeIdentity(3)

	// result of eliminating the first column.
	// [[2,3,4],[0,-1,-2],[0,-5/2,-6]]
	negone := new(ff.Element).Neg(one)
	negtwo := new(ff.Element).Neg(two)
	negFiveDivTwo := new(ff.Element).Neg(five)
	negFiveDivTwo.Div(negFiveDivTwo, two)
	negsix := new(ff.Element).Neg(six)

	// result of eliminating the second column.
	// [[2,3,4],[2/3,0,-2/3],[5/3,0,-8/3]]
	twoDivThree := new(ff.Element).Div(two, three)
	negTwoDivThree := new(ff.Element).Neg(twoDivThree)
	fiveDivThree := new(ff.Element).Div(five, three)
	negEightDivThree := new(ff.Element).Div(eight, three)
	negEightDivThree.Neg(negEightDivThree)

	// result of eliminating the third column.
	// [[2,3,4],[1,1/2,0],[3,2,0]]
	oneDivTwo := new(ff.Element).Div(one, two)

	testMatrix := []struct {
		c    int
		want Matrix
	}{
		{0, Matrix{{two, three, four}, {zero, negone, negtwo}, {zero, negFiveDivTwo, negsix}}},
		{1, Matrix{{two, three, four}, {twoDivThree, zero, negTwoDivThree}, {fiveDivThree, zero, negEightDivThree}}},
		{2, Matrix{{two, three, four}, {one, oneDivTwo, zero}, {three, two, zero}}},
	}

	for _, cases := range testMatrix {
		get, _, err := eliminate(m, shadow, cases.c)
		if err != nil {
			t.Errorf("matrix eliminate failed, err: %s", err)
			return
		}

		if !IsEqual(get, cases.want) {
			t.Errorf("matrix eliminate err, get: %v, want: %v", get, cases.want)
			return
		}
	}
}

func TestReduceToIdentity(t *testing.T) {
	// m=[[1,2,3],[0,3,4],[0,0,3]]
	// m^-1=[[1,-2/3,-1/9],[0,1/3,-4/9],[0,0,1/3]]
	negTwoDivThree := new(ff.Element).Div(two, three)
	negTwoDivThree.Neg(negTwoDivThree)
	negOneDivNine := new(ff.Element).Div(one, nine)
	negOneDivNine.Neg(negOneDivNine)
	oneDivThree := new(ff.Element).Div(one, three)
	negFourDivNine := new(ff.Element).Div(four, nine)
	negFourDivNine.Neg(negFourDivNine)

	// m=[[2,3,4],[0,2,4],[0,0,1]]
	// m^-1=[[1/2,-3/4,1],[0,1/2,-2],[0,0,1]]
	oneDivTwo := new(ff.Element).Div(one, two)
	negThreeDivFour := new(ff.Element).Div(three, four)
	negThreeDivFour.Neg(negThreeDivFour)
	negtwo := new(ff.Element).Neg(two)

	shadow := MakeIdentity(3)

	testMatrix := []struct {
		m    Matrix
		want Matrix
	}{
		{Matrix{{one, two, three}, {zero, three, four}, {zero, zero, three}}, Matrix{{one, negTwoDivThree, negOneDivNine}, {zero, oneDivThree, negFourDivNine}, {zero, zero, oneDivThree}}},
		{Matrix{{two, three, four}, {zero, two, four}, {zero, zero, one}}, Matrix{{oneDivTwo, negThreeDivFour, one}, {zero, oneDivTwo, negtwo}, {zero, zero, one}}},
	}

	for _, cases := range testMatrix {
		_, get, err := reduceToIdentity(cases.m, shadow)
		if err != nil {
			t.Errorf("reduce to identity failed, err: %s", err)
			return
		}

		if !IsEqual(get, cases.want) {
			t.Errorf("reduce err, get:%v, want: %v", get, cases.want)
			return
		}
	}
}

func TestIsInvertible(t *testing.T) {
	testMatrix := []struct {
		m    Matrix
		want bool
	}{
		{Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}, true},
		{Matrix{{one, two, three}, {zero, three, four}, {zero, zero, three}}, true},
		{Matrix{{two, three, four}, {zero, two, four}, {zero, zero, one}}, true},
		{Matrix{{one, two, three}, {four, five, six}, {seven, eight, nine}}, false},
	}

	for _, cases := range testMatrix {
		get := IsInvertible(cases.m)
		if get != cases.want {
			t.Errorf("invert failed, get: %v, want: %v", get, cases.want)
			return
		}
	}
}

func TestInvert(t *testing.T) {
	// 2*2 m:
	// [1 3]
	// [2 7]
	// m^-1:
	// [7 -3]
	// [-2 1]
	negtwo := new(ff.Element).Neg(two)
	negthree := new(ff.Element).Neg(three)

	// 3*3 m:
	// [1 2 3]
	// [0 3 4]
	// [0 0 3]
	// m^-1:
	// [1 -2/3 -1/9]
	// [0 1/3 -4/9]
	// [0 0 1/3]
	negTwoDivThree := new(ff.Element).Div(two, three)
	negTwoDivThree.Neg(negTwoDivThree)
	negOneDivNine := new(ff.Element).Div(one, nine)
	negOneDivNine.Neg(negOneDivNine)
	oneDivThree := new(ff.Element).Div(one, three)
	negFourDivNine := new(ff.Element).Div(four, nine)
	negFourDivNine.Neg(negFourDivNine)

	// 3*3 m:
	// [2 3 4]
	// [4 5 6]
	// [7 8 8]
	// m^-1:
	// [-4 4 -1]
	// [5 -6 2]
	// [-3/2 5/2 -1]
	negone := new(ff.Element).Neg(one)
	negfour := new(ff.Element).Neg(four)
	negsix := new(ff.Element).Neg(six)
	negThreeDivTwo := new(ff.Element).Div(three, two)
	negThreeDivTwo.Neg(negThreeDivTwo)
	fiveDivTwo := new(ff.Element).Div(five, two)

	testMatrix := []struct {
		m    Matrix
		want Matrix
	}{
		{Matrix{{one, three}, {two, seven}}, Matrix{{seven, negthree}, {negtwo, one}}},
		{Matrix{{one, two, three}, {zero, three, four}, {zero, zero, three}}, Matrix{{one, negTwoDivThree, negOneDivNine}, {zero, oneDivThree, negFourDivNine}, {zero, zero, oneDivThree}}},
		{Matrix{{two, three, four}, {four, five, six}, {seven, eight, eight}}, Matrix{{negfour, four, negone}, {five, negsix, two}, {negThreeDivTwo, fiveDivTwo, negone}}},
	}

	for _, cases := range testMatrix {
		res, _ := MatMul(cases.m, cases.want)

		if !IsIdentity(res) {
			t.Error("test cases err")
		}

		get, err := Invert(cases.m)
		if err != nil {
			t.Errorf("invert failed, err: %s", err)
			return
		}

		if !IsEqual(get, cases.want) {
			t.Errorf("invert matrix err, get: %v, want: %v", get, cases.want)
			return
		}
	}
}
