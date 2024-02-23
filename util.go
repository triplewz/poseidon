package poseidon

import (
	"math/big"
)

// hexToElement converts hex-strings to finite field elements
func hexToElement[E Element[E]](hex []string) []E {
	elementArray := make([]E, len(hex))

	for i := 0; i < len(hex); i++ {
		elementArray[i] = newElement[E]()
		_, err := elementArray[i].SetString(hex[i])
		if err != nil {
			panic("Element.SetString failed -> can't parse number in base16 into a big.Int")
		}
	}

	return elementArray
}

// bigToElement converts big integers to finite field elements
func bigToElement[E Element[E]](big []*big.Int) []E {
	elementArray := make([]E, len(big))

	for i := 0; i < len(big); i++ {
		elementArray[i] = newElement[E]()
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
