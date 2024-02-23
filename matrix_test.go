package poseidon

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

var zeroE = new(fr.Element).SetUint64(0)
var oneE = new(fr.Element).SetUint64(1)
var two = new(fr.Element).SetUint64(2)
var three = new(fr.Element).SetUint64(3)
var four = new(fr.Element).SetUint64(4)
var five = new(fr.Element).SetUint64(5)
var six = new(fr.Element).SetUint64(6)
var seven = new(fr.Element).SetUint64(7)
var eight = new(fr.Element).SetUint64(8)
var nine = new(fr.Element).SetUint64(9)

func TestVector(t *testing.T) {
	negTwo := new(fr.Element).Neg(two)

	sub := []struct {
		v1, v2 Vector[*fr.Element]
		want   Vector[*fr.Element]
	}{
		{Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{zeroE, zeroE}},
		{Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{zeroE, zeroE}, Vector[*fr.Element]{oneE, two}},
		{Vector[*fr.Element]{three, four}, Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{two, two}},
		{Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{three, four}, Vector[*fr.Element]{negTwo, negTwo}},
	}

	for _, cases := range sub {
		get, err := VecSub(cases.v1, cases.v2)
		assert.NoError(t, err)
		assert.Equal(t, get, cases.want)
	}

	add := []struct {
		v1, v2 Vector[*fr.Element]
		want   Vector[*fr.Element]
	}{
		{Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{two, four}},
		{Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{zeroE, zeroE}, Vector[*fr.Element]{oneE, two}},
		{Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{oneE, negTwo}, Vector[*fr.Element]{two, zeroE}},
	}

	for _, cases := range add {
		get, err := VecAdd(cases.v1, cases.v2)
		assert.NoError(t, err)
		assert.Equal(t, get, cases.want)
	}

	scalarmul := []struct {
		scalar *fr.Element
		v      Vector[*fr.Element]
		want   Vector[*fr.Element]
	}{
		{zeroE, Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{zeroE, zeroE}},
		{oneE, Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{oneE, two}},
		{two, Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{two, four}},
	}

	for _, cases := range scalarmul {
		get := ScalarVecMul(cases.scalar, cases.v)
		assert.Equal(t, get, cases.want)
	}

	vecmul := []struct {
		v1, v2 Vector[*fr.Element]
		want   *fr.Element
	}{
		{Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{oneE, two}, five},
		{Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{zeroE, zeroE}, zeroE},
		{Vector[*fr.Element]{oneE, two}, Vector[*fr.Element]{negTwo, oneE}, zeroE},
	}

	for _, cases := range vecmul {
		get, err := VecMul(cases.v1, cases.v2)
		assert.NoError(t, err)
		assert.Equal(t, get, cases.want)
	}
}

func TestMatrixScalarMul(t *testing.T) {
	scalarmul := []struct {
		scalar *fr.Element
		m      Matrix[*fr.Element]
		want   Matrix[*fr.Element]
	}{
		{zeroE, Matrix[*fr.Element]{{oneE, two}, {oneE, two}}, Matrix[*fr.Element]{{zeroE, zeroE}, {zeroE, zeroE}}},
		{oneE, Matrix[*fr.Element]{{oneE, two}, {oneE, two}}, Matrix[*fr.Element]{{oneE, two}, {oneE, two}}},
		{two, Matrix[*fr.Element]{{oneE, two}, {three, four}}, Matrix[*fr.Element]{{two, four}, {six, eight}}},
	}

	for _, cases := range scalarmul {
		get := ScalarMul(cases.scalar, cases.m)
		assert.Equal(t, get, cases.want)
	}
}

func TestIdentity(t *testing.T) {
	get := MakeIdentity[*fr.Element](3)
	want := Matrix[*fr.Element]{{oneE, zeroE, zeroE}, {zeroE, oneE, zeroE}, {zeroE, zeroE, oneE}}
	assert.Equal(t, get, want)
}

func TestMinor(t *testing.T) {
	m := Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}

	testMatrix := []struct {
		i, j int
		want Matrix[*fr.Element]
	}{
		{0, 0, Matrix[*fr.Element]{{five, six}, {eight, nine}}},
		{0, 1, Matrix[*fr.Element]{{four, six}, {seven, nine}}},
		{0, 2, Matrix[*fr.Element]{{four, five}, {seven, eight}}},
		{1, 0, Matrix[*fr.Element]{{two, three}, {eight, nine}}},
		{1, 1, Matrix[*fr.Element]{{oneE, three}, {seven, nine}}},
		{1, 2, Matrix[*fr.Element]{{oneE, two}, {seven, eight}}},
		{2, 0, Matrix[*fr.Element]{{two, three}, {five, six}}},
		{2, 1, Matrix[*fr.Element]{{oneE, three}, {four, six}}},
		{2, 2, Matrix[*fr.Element]{{oneE, two}, {four, five}}},
	}

	for _, cases := range testMatrix {
		get, err := minor(m, cases.i, cases.j)
		assert.NoError(t, err)
		assert.Equal(t, get, cases.want)
	}
}

func TestcopyMatrix(t *testing.T) {
	m := Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}

	testMatrix := []struct {
		start, end int
		want       Matrix[*fr.Element]
	}{
		{0, 1, Matrix[*fr.Element]{{oneE, two, three}}},
		{0, 2, Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}}},
		{0, 3, Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}},
		{1, 2, Matrix[*fr.Element]{{four, five, six}}},
		{1, 3, Matrix[*fr.Element]{{four, five, six}, {seven, eight, nine}}},
		{2, 3, Matrix[*fr.Element]{{seven, eight, nine}}},
	}

	for _, cases := range testMatrix {
		get := copyMatrixRows(m, cases.start, cases.end)
		assert.Equal(t, get, cases.want)
	}
}

func TestTranspose(t *testing.T) {
	testMatrix := []struct {
		input, want Matrix[*fr.Element]
	}{
		{Matrix[*fr.Element]{{oneE, two}, {three, four}}, Matrix[*fr.Element]{{oneE, three}, {two, four}}},
		{Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}, Matrix[*fr.Element]{{oneE, four, seven}, {two, five, eight}, {three, six, nine}}},
	}

	for _, cases := range testMatrix {
		get := transpose(cases.input)
		assert.Equal(t, get, cases.want)
	}
}

func TestUpperTriangular(t *testing.T) {
	shadow := MakeIdentity[*fr.Element](3)
	testMatrix := []struct {
		m, s Matrix[*fr.Element]
		want bool
	}{
		{Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}, shadow, true},
		{Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}, shadow, false},
		{Matrix[*fr.Element]{{oneE, two, three}, {zeroE, three, four}, {zeroE, zeroE, three}}, shadow, true},
		{Matrix[*fr.Element]{{two, three, four}, {zeroE, two, four}, {zeroE, zeroE, oneE}}, shadow, true},
	}

	for _, cases := range testMatrix {
		m, _, err := upperTriangular(cases.m, cases.s)
		assert.NoError(t, err)
		get := isUpperTriangular(m)
		assert.Equal(t, get, cases.want)
	}
}

func TestFindNonzeroE(t *testing.T) {
	vectorSet := []struct {
		k    int
		v    Vector[*fr.Element]
		want bool
	}{
		{0, Vector[*fr.Element]{zeroE, oneE, two, three}, false},
		{1, Vector[*fr.Element]{zeroE, oneE, two, three}, true},
		{2, Vector[*fr.Element]{zeroE, oneE, two, three}, false},
		{2, Vector[*fr.Element]{zeroE, zeroE, zeroE, oneE}, true},
		{3, Vector[*fr.Element]{zeroE, zeroE, zeroE, oneE}, true},
		{3, Vector[*fr.Element]{zeroE, oneE, two, three}, false},
		{4, Vector[*fr.Element]{zeroE, oneE, two, three}, false},
	}

	for _, cases := range vectorSet {
		get := isFirstKZero(cases.v, cases.k)
		assert.Equal(t, get, cases.want)
	}

	nonzeroESet := []struct {
		m    Matrix[*fr.Element]
		c    int
		want struct {
			e     *fr.Element
			index int
		}
	}{
		{Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}, 0, struct {
			e     *fr.Element
			index int
		}{two, 0}},
		{Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}, 1, struct {
			e     *fr.Element
			index int
		}{three, 0}},
		{Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}, 2, struct {
			e     *fr.Element
			index int
		}{four, 0}},
		{Matrix[*fr.Element]{{oneE, zeroE, zeroE}, {two, three, zeroE}, {four, five, zeroE}}, 0, struct {
			e     *fr.Element
			index int
		}{oneE, 0}},
		{Matrix[*fr.Element]{{oneE, zeroE, zeroE}, {two, three, zeroE}, {four, five, zeroE}}, 1, struct {
			e     *fr.Element
			index int
		}{three, 1}},
		{Matrix[*fr.Element]{{oneE, zeroE, zeroE}, {two, three, zeroE}, {four, five, zeroE}}, 2, struct {
			e     *fr.Element
			index int
		}{nil, -1}},
	}

	for _, cases := range nonzeroESet {
		gete, geti, err := findNonZero(cases.m, cases.c)
		assert.NoError(t, err)
		if gete != nil && cases.want.e != nil {
			if gete.Cmp(cases.want.e) != 0 || geti != cases.want.index {
				t.Errorf("find non zeroE failed, get element: %v, want element: %v, get index: %d, want index: %d", gete, cases.want.e, geti, cases.want.index)
				return
			}
		} else if gete == nil && cases.want.e == nil {
			if geti != cases.want.index || geti != -1 {
				t.Errorf("find non zeroE failed, get element: %v, want element: %v, get index: %d, want index: %d", gete, cases.want.e, geti, cases.want.index)
				return
			}
		} else {
			t.Errorf("find non zeroE failed, get element: %v, want element: %v, get index: %d, want index: %d", gete, cases.want.e, geti, cases.want.index)
			return
		}
	}
}

func TestMatMul(t *testing.T) {
	// [[1,2,3],[4,5,6],[7,8,9]]*[[2,3,4],[4,5,6],[7,8,8]]
	// =[[31,37,40],[70,85,95],[109,133,148]]
	m00 := new(fr.Element).SetUint64(31)
	m01 := new(fr.Element).SetUint64(37)
	m02 := new(fr.Element).SetUint64(40)
	m10 := new(fr.Element).SetUint64(70)
	m11 := new(fr.Element).SetUint64(85)
	m12 := new(fr.Element).SetUint64(94)
	m20 := new(fr.Element).SetUint64(109)
	m21 := new(fr.Element).SetUint64(133)
	m22 := new(fr.Element).SetUint64(148)

	thirteen := new(fr.Element).SetUint64(13)
	sixteen := new(fr.Element).SetUint64(16)
	eighteen := new(fr.Element).SetUint64(18)

	testMatrix := []struct {
		m1, m2 Matrix[*fr.Element]
		want   Matrix[*fr.Element]
	}{
		{Matrix[*fr.Element]{{zeroE, zeroE}, {zeroE, zeroE}}, Matrix[*fr.Element]{{oneE, two}, {oneE, two}}, Matrix[*fr.Element]{{zeroE, zeroE}, {zeroE, zeroE}}},
		{Matrix[*fr.Element]{{oneE, two}, {two, three}}, Matrix[*fr.Element]{{oneE, two}, {oneE, zeroE}}, Matrix[*fr.Element]{{three, two}, {five, four}}},
		{Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}, Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}, Matrix[*fr.Element]{{m00, m01, m02}, {m10, m11, m12}, {m20, m21, m22}}},
		{Matrix[*fr.Element]{{oneE, oneE, oneE}, {oneE, oneE, oneE}, {oneE, oneE, oneE}}, Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}, Matrix[*fr.Element]{{thirteen, sixteen, eighteen}, {thirteen, sixteen, eighteen}, {thirteen, sixteen, eighteen}}},
		{Matrix[*fr.Element]{{zeroE, zeroE, zeroE}, {zeroE, zeroE, zeroE}, {zeroE, zeroE, zeroE}}, Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}, Matrix[*fr.Element]{{zeroE, zeroE, zeroE}, {zeroE, zeroE, zeroE}, {zeroE, zeroE, zeroE}}},
		{Matrix[*fr.Element]{{oneE, zeroE, zeroE}, {zeroE, oneE, zeroE}, {zeroE, zeroE, oneE}}, Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}, Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}},
	}

	for _, cases := range testMatrix {
		get, err := MatMul(cases.m1, cases.m2)
		assert.NoError(t, err)
		assert.Equal(t, get, cases.want)
	}

	// [[1,2,3],[4,5,6],[7,8,9]]*[1,1,1]
	// =[6,15,24]
	fifteen := new(fr.Element).SetUint64(15)
	twentyfour := new(fr.Element).SetUint64(24)

	testLeftMul := []struct {
		m    Matrix[*fr.Element]
		v    Vector[*fr.Element]
		want Vector[*fr.Element]
	}{
		{Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}, Vector[*fr.Element]{zeroE, zeroE, zeroE}, Vector[*fr.Element]{zeroE, zeroE, zeroE}},
		{Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}, Vector[*fr.Element]{oneE, zeroE, zeroE}, Vector[*fr.Element]{oneE, four, seven}},
		{Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}, Vector[*fr.Element]{oneE, oneE, oneE}, Vector[*fr.Element]{six, fifteen, twentyfour}},
	}

	for _, cases := range testLeftMul {
		get, err := LeftMatMul(cases.m, cases.v)
		assert.NoError(t, err)
		assert.Equal(t, get, cases.want)
	}

	// [1,1,1]*[[1,2,3],[4,5,6],[7,8,9]]
	// =[12,15,18]
	twelve := new(fr.Element).SetUint64(12)

	testRightMul := []struct {
		v    Vector[*fr.Element]
		m    Matrix[*fr.Element]
		want Vector[*fr.Element]
	}{
		{Vector[*fr.Element]{zeroE, zeroE, zeroE}, Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}, Vector[*fr.Element]{zeroE, zeroE, zeroE}},
		{Vector[*fr.Element]{oneE, zeroE, zeroE}, Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}, Vector[*fr.Element]{oneE, two, three}},
		{Vector[*fr.Element]{oneE, oneE, oneE}, Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}, Vector[*fr.Element]{twelve, fifteen, eighteen}},
	}

	for _, cases := range testRightMul {
		get, err := RightMatMul(cases.v, cases.m)
		assert.NoError(t, err)
		assert.Equal(t, get, cases.want)
	}
}

func TestEliminate(t *testing.T) {
	m := Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}
	shadow := MakeIdentity[*fr.Element](3)

	// result of eliminating the first column.
	// [[2,3,4],[0,-1,-2],[0,-5/2,-6]]
	negoneE := new(fr.Element).Neg(oneE)
	negtwo := new(fr.Element).Neg(two)
	negFiveDivTwo := new(fr.Element).Neg(five)
	negFiveDivTwo.Div(negFiveDivTwo, two)
	negsix := new(fr.Element).Neg(six)

	// result of eliminating the second column.
	// [[2,3,4],[2/3,0,-2/3],[5/3,0,-8/3]]
	twoDivThree := new(fr.Element).Div(two, three)
	negTwoDivThree := new(fr.Element).Neg(twoDivThree)
	fiveDivThree := new(fr.Element).Div(five, three)
	negEightDivThree := new(fr.Element).Div(eight, three)
	negEightDivThree.Neg(negEightDivThree)

	// result of eliminating the third column.
	// [[2,3,4],[1,1/2,0],[3,2,0]]
	oneEDivTwo := new(fr.Element).Div(oneE, two)

	testMatrix := []struct {
		c    int
		want Matrix[*fr.Element]
	}{
		{0, Matrix[*fr.Element]{{two, three, four}, {zeroE, negoneE, negtwo}, {zeroE, negFiveDivTwo, negsix}}},
		{1, Matrix[*fr.Element]{{two, three, four}, {twoDivThree, zeroE, negTwoDivThree}, {fiveDivThree, zeroE, negEightDivThree}}},
		{2, Matrix[*fr.Element]{{two, three, four}, {oneE, oneEDivTwo, zeroE}, {three, two, zeroE}}},
	}

	for _, cases := range testMatrix {
		get, _, err := eliminate(m, shadow, cases.c)
		assert.NoError(t, err)
		assert.Equal(t, get, cases.want)
	}
}

func TestReduceToIdentity(t *testing.T) {
	// m=[[1,2,3],[0,3,4],[0,0,3]]
	// m^-1=[[1,-2/3,-1/9],[0,1/3,-4/9],[0,0,1/3]]
	negTwoDivThree := new(fr.Element).Div(two, three)
	negTwoDivThree.Neg(negTwoDivThree)
	negoneEDivNine := new(fr.Element).Div(oneE, nine)
	negoneEDivNine.Neg(negoneEDivNine)
	oneEDivThree := new(fr.Element).Div(oneE, three)
	negFourDivNine := new(fr.Element).Div(four, nine)
	negFourDivNine.Neg(negFourDivNine)

	// m=[[2,3,4],[0,2,4],[0,0,1]]
	// m^-1=[[1/2,-3/4,1],[0,1/2,-2],[0,0,1]]
	oneEDivTwo := new(fr.Element).Div(oneE, two)
	negThreeDivFour := new(fr.Element).Div(three, four)
	negThreeDivFour.Neg(negThreeDivFour)
	negtwo := new(fr.Element).Neg(two)

	shadow := MakeIdentity[*fr.Element](3)

	testMatrix := []struct {
		m    Matrix[*fr.Element]
		want Matrix[*fr.Element]
	}{
		{Matrix[*fr.Element]{{oneE, two, three}, {zeroE, three, four}, {zeroE, zeroE, three}}, Matrix[*fr.Element]{{oneE, negTwoDivThree, negoneEDivNine}, {zeroE, oneEDivThree, negFourDivNine}, {zeroE, zeroE, oneEDivThree}}},
		{Matrix[*fr.Element]{{two, three, four}, {zeroE, two, four}, {zeroE, zeroE, oneE}}, Matrix[*fr.Element]{{oneEDivTwo, negThreeDivFour, oneE}, {zeroE, oneEDivTwo, negtwo}, {zeroE, zeroE, oneE}}},
	}

	for _, cases := range testMatrix {
		_, get, err := reduceToIdentity(cases.m, shadow)
		assert.NoError(t, err)
		assert.Equal(t, get, cases.want)
	}
}

func TestIsInvertible(t *testing.T) {
	testMatrix := []struct {
		m    Matrix[*fr.Element]
		want bool
	}{
		{Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}, true},
		{Matrix[*fr.Element]{{oneE, two, three}, {zeroE, three, four}, {zeroE, zeroE, three}}, true},
		{Matrix[*fr.Element]{{two, three, four}, {zeroE, two, four}, {zeroE, zeroE, oneE}}, true},
		{Matrix[*fr.Element]{{oneE, two, three}, {four, five, six}, {seven, eight, nine}}, false},
	}

	for _, cases := range testMatrix {
		get := IsInvertible(cases.m)
		assert.Equal(t, get, cases.want)
	}
}

func TestInvert(t *testing.T) {
	// 2*2 m:
	// [1 3]
	// [2 7]
	// m^-1:
	// [7 -3]
	// [-2 1]
	negtwo := new(fr.Element).Neg(two)
	negthree := new(fr.Element).Neg(three)

	// 3*3 m:
	// [1 2 3]
	// [0 3 4]
	// [0 0 3]
	// m^-1:
	// [1 -2/3 -1/9]
	// [0 1/3 -4/9]
	// [0 0 1/3]
	negTwoDivThree := new(fr.Element).Div(two, three)
	negTwoDivThree.Neg(negTwoDivThree)
	negoneEDivNine := new(fr.Element).Div(oneE, nine)
	negoneEDivNine.Neg(negoneEDivNine)
	oneEDivThree := new(fr.Element).Div(oneE, three)
	negFourDivNine := new(fr.Element).Div(four, nine)
	negFourDivNine.Neg(negFourDivNine)

	// 3*3 m:
	// [2 3 4]
	// [4 5 6]
	// [7 8 8]
	// m^-1:
	// [-4 4 -1]
	// [5 -6 2]
	// [-3/2 5/2 -1]
	negoneE := new(fr.Element).Neg(oneE)
	negfour := new(fr.Element).Neg(four)
	negsix := new(fr.Element).Neg(six)
	negThreeDivTwo := new(fr.Element).Div(three, two)
	negThreeDivTwo.Neg(negThreeDivTwo)
	fiveDivTwo := new(fr.Element).Div(five, two)

	testMatrix := []struct {
		m    Matrix[*fr.Element]
		want Matrix[*fr.Element]
	}{
		{Matrix[*fr.Element]{{oneE, three}, {two, seven}}, Matrix[*fr.Element]{{seven, negthree}, {negtwo, oneE}}},
		{Matrix[*fr.Element]{{oneE, two, three}, {zeroE, three, four}, {zeroE, zeroE, three}}, Matrix[*fr.Element]{{oneE, negTwoDivThree, negoneEDivNine}, {zeroE, oneEDivThree, negFourDivNine}, {zeroE, zeroE, oneEDivThree}}},
		{Matrix[*fr.Element]{{two, three, four}, {four, five, six}, {seven, eight, eight}}, Matrix[*fr.Element]{{negfour, four, negoneE}, {five, negsix, two}, {negThreeDivTwo, fiveDivTwo, negoneE}}},
	}

	for _, cases := range testMatrix {
		res, _ := MatMul(cases.m, cases.want)
		if !IsIdentity(res) {
			t.Error("test cases err")
		}

		get, err := Invert(cases.m)
		assert.NoError(t, err)
		assert.Equal(t, get, cases.want)
	}
}
