package poseidon

import (
	"github.com/pkg/errors"
	ff "github.com/triplewz/poseidon/bls12_381"
	"math/big"
)

type PoseidonConst struct {
	Mds            *mdsMatrices
	RoundConsts    []*ff.Element
	ComRoundConts  []*ff.Element
	PreSparse      Matrix
	Sparse         []*SparseMatrix
	FullRounds     int
	HalfFullRounds int
	PartialRounds  int
}

// provide three hash modes.
type HashMode int

const (
	// used as the default mode. Consumes statically pre-processed constants for simplest operation.
	OptimizedStatic HashMode = iota
	// the simplified correct hash.
	OptimizedDynamic
	// the initial version of the algorithm in the paper.
	Correct
)

// exponent used in the sbox.
var PoseidonExp = new(big.Int).SetUint64(5)

// Hash implements poseidon hash in this paper: https://eprint.iacr.org/2019/458.pdf.
// we refer the rust implement (OptimizedStatic mode), see https://github.com/filecoin-project/neptune.
// the input length is a slice of big integers.
// the output of poseidon hash is a big integer.
func Hash(input []*big.Int, pdsContants *PoseidonConst, hash HashMode) (*big.Int, error) {
	state := bigToElement(input)

	//state[0] = 0,state[1:width] = input
	zero := new(ff.Element).SetZero()
	state = append([]*ff.Element{zero}, state...)

	//pdsContants, err := genPoseidonConstants(t)
	//if err != nil {
	//	return nil, errors.Errorf("generate poseidon hash err: %s", err)
	//}

	switch hash {
	case OptimizedStatic:
		return optimizedStaticHash(state, pdsContants)
	case OptimizedDynamic:
		return optimizedDynamicHash(state, pdsContants)
	case Correct:
		return correctHash(state, pdsContants)
	default:
		return optimizedStaticHash(state, pdsContants)
	}
}

// generate poseidon constants used in the poseidon hash.
func GenPoseidonConstants(width int) (*PoseidonConst, error) {
	// round numbers.
	rf, rp := calcRoundNumbers(width, true)
	if rf%2 != 0 {
		return nil, errors.Errorf("full rounds should be even!")
	}
	half := rf / 2

	// round constants.
	constants := genRoundConstants(1, 1, ff.Bits, width, rf, rp)

	// mds matrices.
	mds, err := createMDSMatrix(width)
	if err != nil {
		return nil, errors.Errorf("create mds matrix err: %s", err)
	}

	// compressed round constants.
	compress, err := genCompressedRoundConstants(width, rf, rp, constants, mds)
	if err != nil {
		return nil, errors.Errorf("generate compressed round constants err: %s", err)
	}

	// sparse and pre-sparse matrices.
	sparse, preSparse, err := genSparseMatrix(mds.m, rp)
	if err != nil {
		return nil, errors.Errorf("generate sparse matrix err: %s", err)
	}

	return &PoseidonConst{
		Mds:            mds,
		RoundConsts:    constants,
		ComRoundConts:  compress,
		PreSparse:      preSparse,
		Sparse:         sparse,
		FullRounds:     rf,
		PartialRounds:  rp,
		HalfFullRounds: half,
	}, nil
}

func optimizedStaticHash(state []*ff.Element, pdsConsts *PoseidonConst) (*big.Int, error) {
	t := len(state)
	// The first full round should use the initial constants.
	for i := 0; i < t; i++ {
		state[i].Add(state[i], pdsConsts.ComRoundConts[i])
	}

	// do the first half full rounds
	for i := 0; i < pdsConsts.HalfFullRounds; i++ {
		state = staticFullRounds(state, false, i*t+t, pdsConsts)
	}

	// do the partial rounds
	for i := 0; i < pdsConsts.PartialRounds; i++ {
		state = staticPartialRounds(state, i+pdsConsts.HalfFullRounds*t+t, pdsConsts)
	}

	// do the final full rounds
	for i := 0; i < pdsConsts.HalfFullRounds-1; i++ {
		state = staticFullRounds(state, false, i*t+pdsConsts.HalfFullRounds*t+pdsConsts.PartialRounds+t, pdsConsts)
	}

	// last round
	state = staticFullRounds(state, true, -1, pdsConsts)

	// output state[1]
	h := new(big.Int)
	state[1].ToBigIntRegular(h)

	return h, nil
}

func optimizedDynamicHash(state []*ff.Element, pdsConsts *PoseidonConst) (*big.Int, error) {
	t := len(state)
	// The first full round should use the initial constants.
	state = dynamicFullRounds(state, true, true, 0, pdsConsts)

	for i := 0; i < pdsConsts.HalfFullRounds-1; i++ {
		state = dynamicFullRounds(state, false, true, (2+i)*t, pdsConsts)
	}

	state = dynamicPartialRounds(state, pdsConsts)
	for i := 1; i < pdsConsts.PartialRounds; i++ {
		state = partialRounds(state, (pdsConsts.HalfFullRounds+i)*t, pdsConsts)
	}

	for i := 0; i < pdsConsts.HalfFullRounds; i++ {
		state = dynamicFullRounds(state, true, false, (pdsConsts.HalfFullRounds+pdsConsts.PartialRounds+i)*t, pdsConsts)
	}

	// output state[1]
	h := new(big.Int)
	state[1].ToBigIntRegular(h)

	return h, nil
}

func correctHash(state []*ff.Element, pdsConsts *PoseidonConst) (*big.Int, error) {
	t := len(state)

	// do the first half full rounds.
	for i := 0; i < pdsConsts.HalfFullRounds; i++ {
		state = fullRounds(state, i*t, pdsConsts)
	}

	// do the partial rounds.
	for i := 0; i < pdsConsts.PartialRounds; i++ {
		state = partialRounds(state, (pdsConsts.HalfFullRounds+i)*t, pdsConsts)
	}

	// do the final full rounds.
	for i := 0; i < pdsConsts.HalfFullRounds; i++ {
		state = fullRounds(state, (pdsConsts.HalfFullRounds+pdsConsts.PartialRounds+i)*t, pdsConsts)
	}

	// output state[1]
	h := new(big.Int)
	state[1].ToBigIntRegular(h)

	return h, nil
}

// addRoundConsts adds round constants to the input.
func addRoundConsts(state []*ff.Element, RoundConsts []*ff.Element) []*ff.Element {
	for i := 0; i < len(state); i++ {
		state[i].Add(state[i], RoundConsts[i])
	}

	return state
}

// sbox computes x^5 mod p
func sbox(e *ff.Element, pre, post *ff.Element) {
	//if pre is not nil, add round constants before computing the sbox.
	if pre != nil {
		e.Add(e, pre)
	}

	e.Exp(*e, PoseidonExp)

	// if post is not nil, add round constants after computing the sbox.
	if post != nil {
		e.Add(e, post)
	}
}

// staticPartialRounds computes arc->sbox->M, which has partial sbox layers,
// see https://eprint.iacr.org/2019/458.pdf page 6.
// The partial round is the same as the full round, with the difference
// that we apply the S-Box only to the first element.
func staticPartialRounds(state []*ff.Element, offset int, pdsConsts *PoseidonConst) []*ff.Element {
	// swap the order of the linear layer and the round constant addition,
	// see https://eprint.iacr.org/2019/458.pdf page 20.
	sbox(state[0], nil, pdsConsts.ComRoundConts[offset])

	state = productSparseMatrix(state, offset-len(state)*(pdsConsts.HalfFullRounds+1), pdsConsts.Sparse)
	return state
}

// staticFullRounds computes arc->sbox->M, which has full sbox layers,
// see https://eprint.iacr.org/2019/458.pdf page 6.
func staticFullRounds(state []*ff.Element, lastRound bool, offset int, pdsConsts *PoseidonConst) []*ff.Element {
	// in the last round, there is no need to add round constants because
	// we have swapped the order of the linear layer and the round constant addition.
	// see https://eprint.iacr.org/2019/458.pdf page 20.
	if lastRound {
		for i := 0; i < len(state); i++ {
			sbox(state[i], nil, nil)
		}
	} else {
		for i := 0; i < len(state); i++ {
			postKey := pdsConsts.ComRoundConts[offset+i]
			sbox(state[i], nil, postKey)
		}
	}

	// in the fourth full round, we should compute the product between the elements
	// and the pre-sparse matrix (M*M'), see https://eprint.iacr.org/2019/458.pdf page 20.
	if offset == 4*len(state) {
		state = productPreSparseMatrix(state, pdsConsts.PreSparse)
	} else {
		state = productMdsMatrix(state, pdsConsts.Mds.m)
	}

	return state
}

// dynamic partial rounds used in the dynamic hash mode.
func dynamicPartialRounds(state []*ff.Element, pdsContants *PoseidonConst) []*ff.Element {
	// sbox layer.
	sbox(state[0], nil, nil)

	// mixed layer, multiply the elements by the constant MDS matrix.
	state = productMdsMatrix(state, pdsContants.Mds.m)

	return state
}

// dynamic full rounds used in the dynamic hash mode.
func dynamicFullRounds(state []*ff.Element, current, next bool, offset int, pdsContants *PoseidonConst) []*ff.Element {
	t := len(state)
	preRoundKeys := make([]*ff.Element, t)
	postVec := make([]*ff.Element, t)

	// if `current` is true, we need to add the round constants before the sbox layer.
	if current {
		copy(preRoundKeys, pdsContants.RoundConsts[offset:offset+t])
	}

	// if `next` is true, we need to absorb the next round constants after the previous sbox layer.
	if next {
		if current {
			copy(postVec, pdsContants.RoundConsts[offset+t:offset+2*t])
		} else {
			copy(postVec, pdsContants.RoundConsts[offset:offset+t])
		}

		// M^-1(s)
		inv, err := RightMatMul(postVec, pdsContants.Mds.mInv)
		if err != nil {
			panic(err)
		}

		postRoundKeys := make([]*ff.Element, t)
		copy(postRoundKeys, inv)

		// sbox layer.
		for i := 0; i < t; i++ {
			sbox(state[i], preRoundKeys[i], postRoundKeys[i])
		}
	} else {
		// sbox layer.
		for i := 0; i < t; i++ {
			sbox(state[i], preRoundKeys[i], nil)
		}
	}

	// mixed layer, multiply the elements by the constant MDS matrix.
	state = productMdsMatrix(state, pdsContants.Mds.m)
	return state
}

// partial rounds used in the correct hash mode.
func partialRounds(state []*ff.Element, offset int, pdsConsts *PoseidonConst) []*ff.Element {
	// ark.
	state = addRoundConsts(state, pdsConsts.RoundConsts[offset:offset+len(state)])

	// sbox layer.
	sbox(state[0], nil, nil)

	// mixed layer, multiply the elements by the constant MDS matrix.
	state = productMdsMatrix(state, pdsConsts.Mds.m)

	return state
}

// full rounds used in the correct hash mode.
func fullRounds(state []*ff.Element, offset int, pdsConsts *PoseidonConst) []*ff.Element {
	// sbox layer.
	for i := 0; i < len(state); i++ {
		sbox(state[i], pdsConsts.RoundConsts[offset+i], nil)
	}

	// mixed layer, multiply the elements by the constant MDS matrix.
	state = productMdsMatrix(state, pdsConsts.Mds.m)

	return state
}

// productMdsMatrix computes the product between the elements and the mds matrix.
func productMdsMatrix(state []*ff.Element, mds Matrix) []*ff.Element {
	if len(state) != len(mds) {
		panic("cannot compute the product !")
	}

	var res []*ff.Element
	for j := 0; j < len(state); j++ {
		tmp1 := new(ff.Element)
		for i := 0; i < len(state); i++ {
			tmp2 := new(ff.Element).Mul(state[i], mds[i][j])
			tmp1.Add(tmp1, tmp2)
		}
		res = append(res, tmp1)
	}

	//res,err := RightMatMul(state,mds)
	//if err != nil {
	//	panic(err)
	//}
	return res
}

// productPreSparseMatrix computes the product between the elements and the pre-sparse matrix.
func productPreSparseMatrix(state []*ff.Element, preSparseMatrix Matrix) []*ff.Element {
	if len(state) != len(preSparseMatrix) {
		panic("cannot compute the product !")
	}

	var res []*ff.Element
	for j := 0; j < len(state); j++ {
		tmp1 := new(ff.Element)
		for i := 0; i < len(state); i++ {
			tmp2 := new(ff.Element).Mul(state[i], preSparseMatrix[i][j])
			tmp1.Add(tmp1, tmp2)
		}
		res = append(res, tmp1)
	}

	return res
}

// productSparseMatrix computes the product between the elements and the sparse matrix.
func productSparseMatrix(state []*ff.Element, offset int, sparse []*SparseMatrix) []*ff.Element {
	// this part is described in https://eprint.iacr.org/2019/458.pdf page 20.
	// the sparse matrix M'' consists of:
	//
	// M_00  |  v
	// w_hat |  I
	//
	// where M_00 is the first element of the mds matrix,
	// w_hat and v are t-1 length vectors,
	// I is the (t-1)*(t-1) identity matrix.
	// to compute ret = state * M'',
	// we can first compute ret[0] = state * [M_00, w_hat],
	// then for 1 <= i < t,
	// compute ret[i] = state[0] * v[i-1] + state[i].
	res := make([]*ff.Element, len(state))
	res[0] = new(ff.Element)
	for i := 0; i < len(state); i++ {
		tmp := new(ff.Element).Mul(state[i], sparse[offset].wHat[i])
		res[0].Add(res[0], tmp)
	}

	for i := 1; i < len(state); i++ {
		tmp := new(ff.Element).Mul(state[0], sparse[offset].v[i-1])
		res[i] = new(ff.Element).Add(state[i], tmp)
	}

	return res
}
