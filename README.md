# Poseidon Hash
[![Build Status](https://travis-ci.com/triplewz/poseidon.svg?branch=master)](https://travis-ci.com/triplewz/poseidon)

This is the GO implementation of poseidon hash. We refer the paper https://eprint.iacr.org/2019/458.pdf and [the rust implementation](https://github.com/filecoin-project/neptune).
Poseidon hash is a kind of hash function used for proof systems, such as ZK-STARKs, Bulletproof, so it is also called " zero-knowledge friendly hash". It has been widely used in blockchain for zero-knowledge proofs.
You can find more information in the paper.

# Install
`install`:
```bigquery
go get -u github.com/triplewz/poseidon
```
`test`:
```bigquery
go test -v 
```
`benchmark`:
```bigquery
go test -v --bench=. 
```
# Example

```go
func main() {
	// poseidon hash with 3 input elements and 1 output element.
    input := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}

	// generate round constants for poseidon hash.
	// width=len(input)+1.
	cons, _ := GenPoseidonConstants(4)

	// use OptimizedStatic hash mode.
	h1, _ := Hash(input, cons, OptimizedStatic)
	// use OptimizedDynamic hash mode.
	h2, _ := Hash(input, cons, OptimizedDynamic)
	// use Correct hash mode.
	h3, _ := Hash(input, cons, Correct)
}
```
# Benchmark
CPU: i5-9400 CPU @ 2.90GHz.\
OS: win10\
go version: 16.3\
input: 10 elements, output: 1 element

```
BenchmarkOptimizedStaticWith10Inputs-6    	   13419	     89416 ns/op
BenchmarkOptimizedDynamicWith10Inputs-6   	    4693	    251820 ns/op
BenchmarkCorrectWith10Inputs-6            	    5006	    236506 ns/op
```
# Other implementations
- [filecoin-project/neptune](https://github.com/filecoin-project/neptune) (rust)
- [iden3/go-iden3-crypto](https://github.com/iden3/go-iden3-crypto) (go)
- [guipublic/poseidon](https://github.com/guipublic/poseidon) (c)
- [shamatar/poseidon_hash](https://github.com/shamatar/poseidon_hash) (rust)
- [dusk-network/Poseidon252](https://github.com/dusk-network/Poseidon252) (rust)
- [matter-labs/rescue-poseidon](https://github.com/matter-labs/rescue-poseidon) (rust)
- [dusk-network/dusk-poseidon-merkle](https://github.com/dusk-network/dusk-poseidon-merkle) (rust)
- [arnaucube/poseidon-rs](https://github.com/arnaucube/poseidon-rs) (rust)
- [krypto/hadeshash](https://extgit.iaik.tugraz.at/krypto/hadeshash) (sage)

# License
BSD license.