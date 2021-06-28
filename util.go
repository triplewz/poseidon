package poseidon

import (
	ff "github.com/triplewz/poseidon/bls12_381"
	"math/big"
)

// hexToElement converts hex-strings to finite field elements
func hexToElement(hex []string) []*ff.Element {
	elementArray := make([]*ff.Element, len(hex))

	for i := 0; i < len(hex); i++ {
		elementArray[i] = new(ff.Element)
		elementArray[i].SetHexString(hex[i])
	}

	return elementArray
}

// bigToElement converts big integers to finite field elements
func bigToElement(big []*big.Int) []*ff.Element {
	elementArray := make([]*ff.Element, len(big))

	for i := 0; i < len(big); i++ {
		elementArray[i] = new(ff.Element)
		elementArray[i].SetBigInt(big[i])
	}

	return elementArray
}

// hexToBig converts hex-strings to big  integers
func hexToBig(hex []string) []*big.Int {
	bigArray := make([]*big.Int, len(hex))

	for i := 0; i < len(hex); i++ {
		bigArray[i], _ = new(big.Int).SetString(hex[i], 16)
	}

	return bigArray
}
