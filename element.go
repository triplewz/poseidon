package poseidon

import (
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/field/pool"
)

type Element[E any] interface {
	SetUint64(uint64) E
	SetBigInt(*big.Int) E
	SetBytes([]byte) E
	SetString(string) (E, error)
	BigInt(*big.Int) *big.Int
	SetOne() E
	SetZero() E
	Inverse(E) E
	Set(E) E
	Square(E) E
	Mul(E, E) E
	Add(E, E) E
	Sub(E, E) E
	Cmp(x E) int
}

func NewElement[E Element[E]]() E {
	typ := reflect.TypeOf((*E)(nil)).Elem()
	val := reflect.New(typ.Elem())
	return val.Interface().(E)
}

func isNil[E Element[E]](t E) bool {
	v := reflect.ValueOf(t)
	return v.IsNil()
}

func zero[E Element[E]]() E {
	return NewElement[E]().SetZero()
}

func one[E Element[E]]() E {
	return NewElement[E]().SetOne()
}

func Modulus[E Element[E]]() *big.Int {
	e := NewElement[E]().SetZero()
	e.Sub(e, NewElement[E]().SetOne())
	b := e.BigInt(new(big.Int))
	return b.Add(b, big.NewInt(1))
}

func Bits[E Element[E]]() int {
	return Modulus[E]().BitLen()
}

func Bytes[E Element[E]]() int {
	return (Bits[E]() + 7) / 8
}

// Exp is a copy of gnark-crypto's implementation, but takes a pointer argument
func Exp[E Element[E]](z, x E, k *big.Int) {
	if k.IsUint64() && k.Uint64() == 0 {
		z.SetOne()
	}

	e := k
	if k.Sign() == -1 {
		// negative k, we invert
		// if k < 0: xᵏ (mod q) == (x⁻¹)ᵏ (mod q)
		x.Inverse(x)

		// we negate k in a temp big.Int since
		// Int.Bit(_) of k and -k is different
		e = pool.BigInt.Get()
		defer pool.BigInt.Put(e)
		e.Neg(k)
	}

	z.Set(x)

	for i := e.BitLen() - 2; i >= 0; i-- {
		z.Square(z)
		if e.Bit(i) == 1 {
			z.Mul(z, x)
		}
	}
}
