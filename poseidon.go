package poseidon

import (
	"fmt"
	"math/big"
)

type PoseidonConst[E Element[E]] struct {
	Mds             *mdsMatrices[E]
	RoundConsts     []E
	CompRoundConsts []E
	PreSparse       Matrix[E]
	Sparse          []*SparseMatrix[E]
	FullRounds      int
	HalfFullRounds  int
	PartialRounds   int
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
func Hash[E Element[E]](input []*big.Int, pdsContants *PoseidonConst[E], hash HashMode) (*big.Int, error) {
	state := bigToElement[E](input)

	// Neptune (a Rust implementation of Poseidon) is using domain tag 0x3 by default.
	domain_tag, err := newElement[E]().SetString("3")
	if err != nil {
		return nil, err
	}
	state = append([]E{domain_tag}, state...)

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
func GenPoseidonConstants[E Element[E]](width, field, sbox int, roundRoundsUp bool, mds Matrix[E]) (*PoseidonConst[E], error) {
	// round numbers.
	rf, rp := calcRoundNumbers[E](width, true)
	if rf%2 != 0 {
		return nil, fmt.Errorf("full rounds should be even")
	}
	half := rf / 2
	if roundRoundsUp {
		rp += rp % width
	}

	constants := genRoundConstants[E](field, sbox, Bits[E](), width, rf, rp)

	// mds matrices.
	if mds == nil {
		mds = genMDS[E](width)
	}
	mdsm, err := deriveMatrices(mds)
	if err != nil {
		return nil, fmt.Errorf("create mds matrix err: %w", err)
	}

	// compressed round constants.
	compress, err := genCompressedRoundConstants(width, rf, rp, constants, mdsm)
	if err != nil {
		return nil, fmt.Errorf("generate compressed round constants err: %w", err)
	}

	// sparse and pre-sparse matrices.
	sparse, preSparse, err := genSparseMatrix(mdsm.m, rp)
	if err != nil {
		return nil, fmt.Errorf("generate sparse matrix err: %w", err)
	}

	return &PoseidonConst[E]{
		Mds:             mdsm,
		RoundConsts:     constants,
		CompRoundConsts: compress,
		PreSparse:       preSparse,
		Sparse:          sparse,
		FullRounds:      rf,
		PartialRounds:   rp,
		HalfFullRounds:  half,
	}, nil
}

func optimizedStaticHash[E Element[E]](state []E, pdsConsts *PoseidonConst[E]) (*big.Int, error) {
	t := len(state)
	// The first full round should use the initial constants.
	for i := 0; i < t; i++ {
		state[i].Add(state[i], pdsConsts.CompRoundConsts[i])
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
	state[1].BigInt(h)

	return h, nil
}

func optimizedDynamicHash[E Element[E]](state []E, pdsConsts *PoseidonConst[E]) (*big.Int, error) {
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
	state[1].BigInt(h)

	return h, nil
}

func correctHash[E Element[E]](state []E, pdsConsts *PoseidonConst[E]) (*big.Int, error) {
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
	state[1].BigInt(h)

	return h, nil
}

// addRoundConsts adds round constants to the input.
func addRoundConsts[E Element[E]](state []E, RoundConsts []E) []E {
	for i := 0; i < len(state); i++ {
		state[i].Add(state[i], RoundConsts[i])
	}

	return state
}

// sbox computes x^5 mod p
func sbox[E Element[E]](e E, pre, post *E) {
	//if pre is not nil, add round constants before computing the sbox.
	if pre != nil && !isNil(*pre) {
		e.Add(e, *pre)
	}

	x := newElement[E]().Set(e)
	Exp(e, x, PoseidonExp)

	// if post is not nil, add round constants after computing the sbox.
	if post != nil && !isNil(*post) {
		e.Add(e, *post)
	}
}

// staticPartialRounds computes arc->sbox->m, which has partial sbox layers,
// see https://eprint.iacr.org/2019/458.pdf page 6.
// The partial round is the same as the full round, with the difference
// that we apply the S-Box only to the first element.
func staticPartialRounds[E Element[E]](state []E, offset int, pdsConsts *PoseidonConst[E]) []E {
	// swap the order of the linear layer and the round constant addition,
	// see https://eprint.iacr.org/2019/458.pdf page 20.
	sbox(state[0], nil, &pdsConsts.CompRoundConsts[offset])

	state = productSparseMatrix(state, offset-len(state)*(pdsConsts.HalfFullRounds+1), pdsConsts.Sparse)
	return state
}

// staticFullRounds computes arc->sbox->m, which has full sbox layers,
// see https://eprint.iacr.org/2019/458.pdf page 6.
func staticFullRounds[E Element[E]](state []E, lastRound bool, offset int, pdsConsts *PoseidonConst[E]) []E {
	// in the last round, there is no need to add round constants because
	// we have swapped the order of the linear layer and the round constant addition.
	// see https://eprint.iacr.org/2019/458.pdf page 20.
	if lastRound {
		for i := 0; i < len(state); i++ {
			sbox(state[i], nil, nil)
		}
	} else {
		for i := 0; i < len(state); i++ {
			postKey := pdsConsts.CompRoundConsts[offset+i]
			sbox(state[i], nil, &postKey)
		}
	}

	// in the fourth full round, we should compute the product between the elements
	// and the pre-sparse matrix (m*m'), see https://eprint.iacr.org/2019/458.pdf page 20.
	if offset == 4*len(state) {
		state = productPreSparseMatrix(state, pdsConsts.PreSparse)
	} else {
		state = productMdsMatrix(state, pdsConsts.Mds.m)
	}

	return state
}

// dynamic partial rounds used in the dynamic hash mode.
func dynamicPartialRounds[E Element[E]](state []E, pdsContants *PoseidonConst[E]) []E {
	// sbox layer.
	sbox(state[0], nil, nil)

	// mixed layer, multiply the elements by the constant MDS matrix.
	state = productMdsMatrix(state, pdsContants.Mds.m)

	return state
}

// dynamic full rounds used in the dynamic hash mode.
func dynamicFullRounds[E Element[E]](state []E, current, next bool, offset int, pdsContants *PoseidonConst[E]) []E {
	t := len(state)
	preRoundKeys := make([]E, t)
	postVec := make([]E, t)

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

		// m^-1(s)
		inv, err := RightMatMul(postVec, pdsContants.Mds.mInv)
		if err != nil {
			panic(err)
		}

		postRoundKeys := make([]E, t)
		copy(postRoundKeys, inv)

		// sbox layer.
		for i := 0; i < t; i++ {
			sbox(state[i], &preRoundKeys[i], &postRoundKeys[i])
		}
	} else {
		// sbox layer.
		for i := 0; i < t; i++ {
			sbox(state[i], &preRoundKeys[i], nil)
		}
	}

	// mixed layer, multiply the elements by the constant MDS matrix.
	state = productMdsMatrix(state, pdsContants.Mds.m)
	return state
}

// partial rounds used in the correct hash mode.
func partialRounds[E Element[E]](state []E, offset int, pdsConsts *PoseidonConst[E]) []E {
	// ark.
	state = addRoundConsts(state, pdsConsts.RoundConsts[offset:offset+len(state)])

	// sbox layer.
	sbox(state[0], nil, nil)

	// mixed layer, multiply the elements by the constant MDS matrix.
	state = productMdsMatrix(state, pdsConsts.Mds.m)

	return state
}

// full rounds used in the correct hash mode.
func fullRounds[E Element[E]](state []E, offset int, pdsConsts *PoseidonConst[E]) []E {
	// sbox layer.
	for i := 0; i < len(state); i++ {
		sbox(state[i], &pdsConsts.RoundConsts[offset+i], nil)
	}

	// mixed layer, multiply the elements by the constant MDS matrix.
	state = productMdsMatrix(state, pdsConsts.Mds.m)

	return state
}

// productMdsMatrix computes the product between the elements and the mds matrix.
func productMdsMatrix[E Element[E]](state []E, mds Matrix[E]) []E {
	if len(state) != len(mds) {
		panic("cannot compute the product !")
	}

	var res []E
	for j := 0; j < len(state); j++ {
		tmp1 := newElement[E]()
		for i := 0; i < len(state); i++ {
			tmp2 := newElement[E]().Mul(state[i], mds[i][j])
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
func productPreSparseMatrix[E Element[E]](state []E, preSparseMatrix Matrix[E]) []E {
	if len(state) != len(preSparseMatrix) {
		panic("cannot compute the product !")
	}

	var res []E
	for j := 0; j < len(state); j++ {
		tmp1 := newElement[E]()
		for i := 0; i < len(state); i++ {
			tmp2 := newElement[E]().Mul(state[i], preSparseMatrix[i][j])
			tmp1.Add(tmp1, tmp2)
		}
		res = append(res, tmp1)
	}

	return res
}

// productSparseMatrix computes the product between the elements and the sparse matrix.
func productSparseMatrix[E Element[E]](state []E, offset int, sparse []*SparseMatrix[E]) []E {
	// this part is described in https://eprint.iacr.org/2019/458.pdf page 20.
	// the sparse matrix m'' consists of:
	//
	// M_00  |  V
	// w_hat |  I
	//
	// where M_00 is the first element of the mds matrix,
	// w_hat and V are t-1 length vectors,
	// I is the (t-1)*(t-1) identity matrix.
	// to compute ret = state * m'',
	// we can first compute ret[0] = state * [M_00, w_hat],
	// then for 1 <= i < t,
	// compute ret[i] = state[0] * V[i-1] + state[i].
	res := make([]E, len(state))
	res[0] = newElement[E]()
	for i := 0; i < len(state); i++ {
		tmp := newElement[E]().Mul(state[i], sparse[offset].WHat[i])
		res[0].Add(res[0], tmp)
	}

	for i := 1; i < len(state); i++ {
		tmp := newElement[E]().Mul(state[0], sparse[offset].V[i-1])
		res[i] = newElement[E]().Add(state[i], tmp)
	}

	return res
}
