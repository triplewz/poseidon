package poseidon

import (
	"fmt"
	"math"
	"math/big"
)

// security level (in bits)
const SecurityLevel int = 128

// we refer the rust implement and supplementary material shown in the paper to generate the round numbers.
// see https://extgit.iaik.tugraz.at/krypto/hadeshash.
func calcRoundNumbers[E Element[E]](t int, securityMargin bool) (rf, rp int) {
	rf, rp = 0, 0
	min := math.MaxInt64

	// Brute-force approach
	for rft := 2; rft <= 1000; rft += 2 {
		for rpt := 4; rpt < 200; rpt++ {
			if isRoundNumberSecure[E](t, rft, rpt) {
				// https://eprint.iacr.org/2019/458.pdf page 9.
				if securityMargin {
					rft += 2
					rpt = int(math.Ceil(1.075 * float64(rpt)))
				}
				sboxn := t*rft + rpt
				if sboxn < min || (sboxn == min && rft < rf) {
					rp = int(math.Ceil(float64(rpt)))
					rf = int(math.Ceil(float64(rft)))
					min = sboxn
				}
			}
		}
	}

	return
}

// isRoundNumberSecure determines if the round numbers are secure.
func isRoundNumberSecure[E Element[E]](t, rf, rp int) bool {
	// n is the number of bits of p.
	n := Bits[E]()

	// Statistical Attacks
	// https://eprint.iacr.org/2019/458.pdf page 10.
	var rf0 int
	if SecurityLevel <= (n-2)*(t+1) {
		rf0 = 6
	} else {
		rf0 = 10
	}

	// Interpolation Attack. https://eprint.iacr.org/2019/458.pdf page 10.
	// rf1 := 1+math.Ceil(math.Log(2)/math.Log(float64(Alpha))*float64(SecurityLevel))+math.Ceil(math.Log(float64(t))/math.Log(float64(Alpha))) - float64(rp)
	rf1 := 0.43*float64(SecurityLevel) + math.Log2(float64(t)) - float64(rp)

	// Gröbner Basis Attack (1). https://eprint.iacr.org/2019/458.pdf page 10.
	// rf2 := math.Log(2)/math.Log(float64(Alpha))*math.Min(float64(SecurityLevel)/3,float64(n)/2)-float64(rp)
	rf2 := 0.21*float64(n) - float64(rp)

	// Gröbner Basis Attack (2).
	// rf3 := float64(t)-1+math.Min((math.Log(2)*float64(SecurityLevel))/(math.Log(float64(Alpha))*(float64(t)+1)),math.Log(2)*float64(n)/(2.0*math.Log(float64(Alpha))))
	rf3 := (0.14*float64(n) - 1 - float64(rp)) / (float64(t) - 1)

	max := math.Max(math.Max(float64(rf0), rf1), math.Max(rf2, rf3))

	return float64(rf) >= max
}

// appendBits converts a number to the bit slice.
// For simplicity, we use uint8 1 or 0 to represent a bit.
func appendBits(bits []byte, n, size int) []byte {
	for i := size - 1; i >= 0; i-- {
		bitmask := 1 << i
		b := (n & bitmask) >> i
		bits = append(bits, byte(b))
	}

	return bits
}

// genNewBits generates new 80-bits slice and returns the newly generated bit.
func genNewBits(bits []byte) byte {
	newBit := bits[0] ^ bits[13] ^ bits[23] ^ bits[38] ^ bits[51] ^ bits[62]
	newBits := append(bits, newBit)
	copy(bits, newBits[1:])
	return newBit
}

// nextByte converts bits to byte.
func nextByte(bits []byte, bitCount int) byte {
	var b byte
	for i := 0; i < bitCount; i++ {
		newBit := genNewBits(bits)
		for newBit == 0 {
			genNewBits(bits)
			newBit = genNewBits(bits)
		}
		newBit = genNewBits(bits)

		b <<= 1
		if newBit == 1 {
			b += 1
		}
	}
	return b
}

// getBytes generates a random byte slice.
func getBytes[E Element[E]](bits []byte, fieldsize int) []byte {
	// Only prime fields are supported, and they always have reminder bits.
	remainderBits := fieldsize % 8

	bytes := Bytes[E]()
	buf := make([]byte, bytes)
	buf[0] = nextByte(bits, remainderBits)

	// The first byte is already set.
	for i := 1; i < bytes; i++ {
		buf[i] = nextByte(bits, 8)
	}

	return buf
}

// The round constants are generated using the Grain LFSR in a self-shrinking
// mode:
// 1. Initialize the state with 80 bits b0, b1, . . . , b79, where
// (a) b0, b1 describe the field,
// (b) bi for 2 ≤ i ≤ 5 describe the S-Box,
// (c) bi for 6 ≤ i ≤ 17 are the binary representation of n,
// (d) bi for 18 ≤ i ≤ 29 are the binary representation of t,
// (e) bi for 30 ≤ i ≤ 39 are the binary representation of RF ,
// (f) bi for 40 ≤ i ≤ 49 are the binary representation of RP , and
// (g) bi for 50 ≤ i ≤ 79 are set to 1.
// 2. Update the bits using bi+80 = bi+62 ⊕ bi+51 ⊕ bi+38 ⊕ bi+23 ⊕ bi+13 ⊕ bi
// .
// 3. Discard the first 160 bits.
// 4. Evaluate bits in pairs: If the first bit is a 1, output the second bit. If it is a
// 0, discard the second bit.
// Using this method, the generation of round constants depends on the specific
// instance, and thus different round constants are used even if some of the chosen
// parameters (e.g., n and t) are the same.
// Note that cryptographically strong randomness is not needed for the
// round constants, and other methods can also be used.
func genRoundConstants[E Element[E]](field, sbox int, fieldsize, t, rf, rp int) []E {
	numCons := (rf + rp) * t

	var bits []byte
	bits = appendBits(bits, field, 2)
	bits = appendBits(bits, sbox, 4)
	bits = appendBits(bits, fieldsize, 12)
	bits = appendBits(bits, t, 12)
	bits = appendBits(bits, rf, 10)
	bits = appendBits(bits, rp, 10)
	bits = appendBits(bits, (1<<30)-1, 30)

	for i := 0; i < 160; i++ {
		genNewBits(bits)
	}

	roundConsts := make([]E, numCons)
	for i := 0; i < numCons; i++ {
		for {
			buf := getBytes[E](bits, fieldsize)
			bufBigint := new(big.Int).SetBytes(buf)
			// Skip all buffers that would result in invalid field elements.
			if IsValid[E](bufBigint) {
				roundConsts[i] = NewElement[E]().SetBytes(buf)
				break
			}
		}
	}

	return roundConsts
}

func IsValid[E Element[E]](z *big.Int) bool {
	return z.Cmp(Modulus[E]()) == -1
}

// compress constants by pushing them back through linear layers and through the identity components of partial layers.
// as a result, constants need only be added after each S-box.
// see https://eprint.iacr.org/2019/458.pdf page 20.
// in our implementation, we compress all constants in partial rounds.
func genCompressedRoundConstants[E Element[E]](width, rf, rp int, roundConstants []E, mds *mdsMatrices[E]) ([]E, error) {
	comRoundConstants := make([]E, rf*width+rp)
	mInv := mds.mInv

	// first round constants
	copy(comRoundConstants[:width], roundConstants[:width])

	end := rf/2 - 1
	// first half full-rounds
	for i := 0; i < end; i++ {
		nextRound := roundConstants[(i+1)*width : (i+2)*width]
		inv, err := RightMatMul(nextRound, mInv)
		if err != nil {
			return nil, fmt.Errorf("full round constants mul err: %w", err)
		}
		copy(comRoundConstants[(i+1)*width:(i+2)*width], inv)
	}

	// partial rounds
	lastPartialRound := rf/2 + rp
	lastPartialRoundKey := roundConstants[lastPartialRound*width : (lastPartialRound+1)*width]

	partialKeys := make([]E, rp)
	roundAcc := make([]E, width)
	preRoundKeys := make([]E, width)
	copy(roundAcc, lastPartialRoundKey)
	for i := 0; i < rp; i++ {
		inv, err := RightMatMul(roundAcc, mInv)
		if err != nil {
			return nil, fmt.Errorf("partial key err: %w", err)
		}
		partialKeys[i] = inv[0]
		inv[0] = zero[E]()
		copy(preRoundKeys, roundConstants[(lastPartialRound-i-1)*width:(lastPartialRound-i)*width])
		roundAcc, err = VecAdd(preRoundKeys, inv)
		if err != nil {
			return nil, fmt.Errorf("round accumulated err: %w", err)
		}
	}

	// the accumulated result.
	acc, err := RightMatMul(roundAcc, mInv)
	if err != nil {
		return nil, fmt.Errorf("last round key err: %w", err)
	}
	copy(comRoundConstants[(rf/2)*width:(rf/2+1)*width], acc)

	// revert the partial keys.
	for i := 0; i < rp; i++ {
		comRoundConstants[(rf/2+1)*width+i] = partialKeys[rp-i-1]
	}

	// final 3 full-rounds.
	for i := 1; i < rf/2; i++ {
		constants := roundConstants[(rf/2+rp+i)*width : (rf/2+rp+i+1)*width]
		inv, err := RightMatMul(constants, mInv)
		if err != nil {
			return nil, fmt.Errorf("final full round key err: %w", err)
		}
		copy(comRoundConstants[(rf/2+i)*width+rp:(rf/2+i+1)*width+rp], inv)
	}

	return comRoundConstants, nil
}
