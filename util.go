package poseidon

import (
	"math/big"
)

// hexToElement converts hex-strings to finite field elements
func hexToElement[E Element[E]](hex []string) []E {
	elementArray := make([]E, len(hex))

	for i := 0; i < len(hex); i++ {
		elementArray[i] = NewElement[E]()
		b, ok := new(big.Int).SetString(hex[i], 16)
		if !ok {
			panic("Element.SetString failed -> can't parse number in base16 into a big.Int")
		}
		elementArray[i].SetBigInt(b)
	}

	return elementArray
}

// bigToElement converts big integers to finite field elements
func bigToElement[E Element[E]](big []*big.Int) []E {
	elementArray := make([]E, len(big))

	for i := 0; i < len(big); i++ {
		elementArray[i] = NewElement[E]()
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
