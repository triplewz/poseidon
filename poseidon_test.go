package poseidon

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	ff "github.com/triplewz/poseidon/bls12_381"
	"os"
	"testing"
)

func TestPoseidonConstans(t *testing.T) {
	// the given poseidon round constants are as follows:
	// modular: 73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
	// bits: 255
	// width: 12
	// rf: 8
	// rp: 57
	// security level(in bits): 128
	// security margin: true
	// alpha: 5
	f, err := os.Open("./data/poseidon-constants-1-1-255-12-8-57-73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001.txt")
	assert.NoError(t, err)
	defer f.Close()

	var strs struct {
		CompressedRoundConstants []string     `json:"compress"`
		RoundConstants           []string     `json:"constants"`
		Mds                      [][]string   `json:"mds"`
		Sparse                   [][][]string `json:"sparse"`
		PreSparse                [][]string   `json:"pre_sparse"`
	}

	buf := make([]byte, 256*1024)
	n, err := f.Read(buf)
	assert.NoError(t, err)
	err = json.Unmarshal(buf[:n], &strs)
	assert.NoError(t, err)

	// compressed round constants
	comRoundConstants := hexToElement(strs.CompressedRoundConstants)

	// round constants
	roundConstants := hexToElement(strs.RoundConstants)

	// mds matrix
	mdsMatrix := make([][]*ff.Element, len(strs.Mds))
	for i := 0; i < len(strs.Mds); i++ {
		mdsMatrix[i] = hexToElement(strs.Mds[i])
	}

	// pre-sparse matrix
	preSparseMatrix := make([][]*ff.Element, len(strs.PreSparse))
	for i := 0; i < len(strs.PreSparse); i++ {
		preSparseMatrix[i] = hexToElement(strs.PreSparse[i])
	}

	// sparse matrix
	sparseMatrix := make([][][]*ff.Element, len(strs.Sparse))
	for i := 0; i < len(strs.Sparse); i++ {
		sparseMatrix[i] = make([][]*ff.Element, len(strs.Sparse[i]))
		for j := 0; j < len(strs.Sparse[i]); j++ {
			sparseMatrix[i][j] = hexToElement(strs.Sparse[i][j])
		}
	}

	mds, _ := deriveMatrices(mdsMatrix)
	// test mds matrices
	mul0, _ := MatMul(mds.m, mds.mInv)
	mul1, _ := MatMul(mds.mHat, mds.mHatInv)
	mul2, _ := MatMul(mds.mPrime, mds.mDoublePrime)
	if !IsIdentity(mul0) || !IsIdentity(mul1) || !IsEqual(mul2, mds.m) {
		t.Error("got wrong mds matrices!")
		return
	}

	sparse, preSparse, _ := genSparseMatrix(mdsMatrix, 57)
	if !IsEqual(preSparse, preSparseMatrix) {
		t.Error("got wrong pre-sparse matrix!")
		return
	}

	for i := 0; i < 57; i++ {
		if !IsVecEqual(sparseMatrix[i][0], sparse[i].wHat) || !IsVecEqual(sparseMatrix[i][1], sparse[i].v) {
			t.Error("got wrong sparse matrix!")
			return
		}
	}

	compress, _ := genCompressedRoundConstants(12, 8, 57, roundConstants, mds)
	assert.Equal(t, compress, comRoundConstants)
}

var strs = [][]string{
	{"56af805edfdbcf14bf6b229e24cb35a2d8e8b41f2f77f330ad1ec81e87124091"},
	{"596dba158fce9264697ba28a9132cf13bee36ddeae64bd383028f7f9a7d7ccbe", "17ec2fd54bd7cc9e00308ee754ff2f57965cbd5196938f48226f924a4c3f2222"},
	{"3a6dfeabe50a2a71d3f9da8ade3e4182dd2f93c7fcf2e753440ffa26f0230fa9", "44d3a6cb4f7125dd4ca8a2df2c0d61a667375ab07e5732cc44fbb093e83f5a1c", "4a242c4026565b1540f75a064cbdd0d5a4c390ee59ab068863e379a9be79072e"},
	{"2913b2dd50fb4aa594f5e9dbf0c732c5ab1dd93749beb712f446f3f379c30697", "44609d7c0763a09c062c1cbf3f4e565f961858309b56914c51f87859eae3ab54", "596fefdfa3b258ae0aedf58f7aa73e98dd0f157b2602a8b474b04f42edf9d2f7", "423b7ad3929216a667e0f751eaf99d81e446c341d97f3088ab9452c65a12f513"},
	{"5b3c641e67e7c355fec707e6906a9bbcf732dfc5f30cabb0fca69edd6820d913", "713f63b9d3355f1f3825a6068f80e8efce685f95d9aef6f00e99c986d4eced3b", "1fc5c54d68c3dad08d2732a0ddf8278ab022a9e61619e4b3011933a5e765f0a3", "34354feebc3a7aae6ca359965d165ad2de96c7bf67ade0ad98adcc03018ad1e6", "3462ab3e4173a9962a9bda8a31b6e8e8bd1094ad834734cd9ca341b6cc0f4865"},
	{"2277d188711fd8309052301545b64ecb7a504e805b2ff94a4e2584a72f747c49", "19adabddf44b141055701f117f65cdde99bc41d9ed3772452372929c7843dfb9", "1748b9461ccd049d5791c9fa34ece69ae58867c44ca0e214da9c32c53bcb24ba", "6b153b8e04fdb6fb8f2fe9976fe4300d0a6c224af3b55da0fd6d57564996ccab", "37ca71a539feb4e147895bbeaddd6b2a4a9774dd3cc7cdf761655b33eee97b8f", "16fa8134a940aee04cafaeb8a46fed7fbe6bcf5e23835d817f570ada1796dbad"},
	{"35dfd308fa11cd021e97d3d4fc4d9ad336756c4b6e7faf7cbae175dac6e8c39f", "71a7ec189f479b7c8d223c3a01e5efee797cfed96a604f6bf0c8fe95d907ec14", "6baa24a357daa7885d6bcc3cc8b26478bce7a5f1a45c9513d9f810ff029520f9", "307c343afda8c673c8d9ac4e9235c8c8d48e6f33ed3a66fddae0999275b8bdfb", "105462a0727238a91b7d94bd904219eb8cb4e4421e6fb5778aa0c255a4e20de2", "56ba5b8658970df796b555cedf63cae1a69174fbd5ff750a7b93c9ac0a5723f2", "4908f83610f441c608570328f77214ec2d33e68eb7fac63e7fc83a2d4a908e29"},
	{"3559b81ad6bee99ca9f70f476cc99bdbaa8be84fa9a45b024184ec68afacb4a3", "596a94367afcc3ee594bba34207deba542a35e1856384fb719991d9f52c6d5b6", "4a57bdfed8b44426fcbdcf43e1f52c9507554c8f0c30bca9ad53a7b4b3ed0c78", "350ced55431daffb76ddbd40c15d7ab4f638822a9e853fa9e7dd464292e0352e", "6ba6fef4148e07220aee89fffa45b018099c388cd9f3da7d4e7b66748b8ed9c8", "6eff173c0195e60b42ce9f77278aea092451da626113793d699b00f0d2f72722", "3d127305d3427cf83864be88b16897982cc352504c3d0f02e67cb0df7073c935", "5cf3b4f87cf4e2f6dc062956f1b841af16f9e407a01109277369cfb6215c92cc"},
	{"571b68764e1ad1e4baa2ce6114c19ff0a7a1de3fc8d0ec553db168fbc8d70afa", "5dcc355ee0b6ef63b336e1e6f1e6cc4a80d5c1343ea0e511bf8fd92bb345c5ab", "516fb541bcc7da6130d20b6153687de7488bc0719098551b4ce27b717f42b705", "48965e83ec245e9254f2abbdc0159b896672b5ca02ad89669cd45aa4c242f6ec", "5563232abec4f39776ec43f71bd6d68e256e4b7b7993b93d45a3103167cd7b51", "115f3ad2bd0b42ce1a340ae08f65919e835d7fdcb08ac57a9c5f22273503e2dc", "64fe7104aee1d2820a25529b4d3ba25495625615bf2a8c26da6792b3dd6e4d38", "67fd80616f659040a796c3b07875a357befcc568770ffb12b5e20718027df551", "300fd123e2db381e7c62f6ff805afec009f78e3084c53c4b0a0e15f1d3c47432"},
	{"29e5b0b730bede2b25109bf90d5bd19c0e54aa4a1c7534989672d7ce00bdd744", "4e150a64f824a55cd173f4811aa702481250074bd6932f4ad128d03e9c563cda", "6d2cbd6e9ccdc268a3d394dc397890d50c1759dfb6fa5d74c417b752e513c165", "6506b40b833a3b3892ab4153e0706be955f2a9b6fe23ef7336510e28a3385cc", "6615f47dc88793ccee3baca56749a514bf64ebdade2e64c9b510ef07ec338f6d", "1b0ce51487cb14298c5bf5f96a2780a6df342e784f47be15d5a3e2c33c34967e", "21a14fc5c4938077f74b463d27299c5cfd789fe2a0b34d1da03510dab7f81d5c", "1135416dd9f383fdebfce19f87048d01392f9875026a1ff3579100d0e20032c", "67d826815b936275464ef96b909ddc9942359d878e979c5ce3a5fd78370aa37c", "634fa094f715b22e1a04e9b06a2503e712bb2e3552a1723266b2098e3afd2557"},
}

func TestPoseidonHash(t *testing.T) {
	for i := 0; i < len(strs); i++ {
		cons, _ := GenPoseidonConstants(len(strs[i]) + 1)
		input := hexToBig(strs[i])
		h1, _ := Hash(input, cons, OptimizedStatic)
		h2, _ := Hash(input, cons, OptimizedDynamic)
		h3, _ := Hash(input, cons, Correct)
		assert.Equal(t, h1, h2)
		assert.Equal(t, h1, h3)
	}
}

func benchmarkStatic(b *testing.B, str []string) {
	cons, _ := GenPoseidonConstants(len(str) + 1)
	input := hexToBig(str)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Hash(input, cons, OptimizedStatic)
	}
}

func BenchmarkOptimizedStaticWith1Input(b *testing.B)   { benchmarkStatic(b, strs[0]) }
func BenchmarkOptimizedStaticWith2Inputs(b *testing.B)  { benchmarkStatic(b, strs[1]) }
func BenchmarkOptimizedStaticWith3Inputs(b *testing.B)  { benchmarkStatic(b, strs[2]) }
func BenchmarkOptimizedStaticWith4Inputs(b *testing.B)  { benchmarkStatic(b, strs[3]) }
func BenchmarkOptimizedStaticWith5Inputs(b *testing.B)  { benchmarkStatic(b, strs[4]) }
func BenchmarkOptimizedStaticWith6Inputs(b *testing.B)  { benchmarkStatic(b, strs[5]) }
func BenchmarkOptimizedStaticWith7Inputs(b *testing.B)  { benchmarkStatic(b, strs[6]) }
func BenchmarkOptimizedStaticWith8Inputs(b *testing.B)  { benchmarkStatic(b, strs[7]) }
func BenchmarkOptimizedStaticWith9Inputs(b *testing.B)  { benchmarkStatic(b, strs[8]) }
func BenchmarkOptimizedStaticWith10Inputs(b *testing.B) { benchmarkStatic(b, strs[9]) }

func benchmarkDynamic(b *testing.B, str []string) {
	cons, _ := GenPoseidonConstants(len(str) + 1)
	input := hexToBig(str)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Hash(input, cons, OptimizedDynamic)
	}
}

func BenchmarkOptimizedDynamicWith1Input(b *testing.B)   { benchmarkDynamic(b, strs[0]) }
func BenchmarkOptimizedDynamicWith2Inputs(b *testing.B)  { benchmarkDynamic(b, strs[1]) }
func BenchmarkOptimizedDynamicWith3Inputs(b *testing.B)  { benchmarkDynamic(b, strs[2]) }
func BenchmarkOptimizedDynamicWith4Inputs(b *testing.B)  { benchmarkDynamic(b, strs[3]) }
func BenchmarkOptimizedDynamicWith5Inputs(b *testing.B)  { benchmarkDynamic(b, strs[4]) }
func BenchmarkOptimizedDynamicWith6Inputs(b *testing.B)  { benchmarkDynamic(b, strs[5]) }
func BenchmarkOptimizedDynamicWith7Inputs(b *testing.B)  { benchmarkDynamic(b, strs[6]) }
func BenchmarkOptimizedDynamicWith8Inputs(b *testing.B)  { benchmarkDynamic(b, strs[7]) }
func BenchmarkOptimizedDynamicWith9Inputs(b *testing.B)  { benchmarkDynamic(b, strs[8]) }
func BenchmarkOptimizedDynamicWith10Inputs(b *testing.B) { benchmarkDynamic(b, strs[9]) }

func benchmarkCorrect(b *testing.B, str []string) {
	cons, _ := GenPoseidonConstants(len(str) + 1)
	input := hexToBig(str)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Hash(input, cons, Correct)
	}
}

func BenchmarkCorrectWith1Input(b *testing.B)   { benchmarkCorrect(b, strs[0]) }
func BenchmarkCorrectWith2Inputs(b *testing.B)  { benchmarkCorrect(b, strs[1]) }
func BenchmarkCorrectWith3Inputs(b *testing.B)  { benchmarkCorrect(b, strs[2]) }
func BenchmarkCorrectWith4Inputs(b *testing.B)  { benchmarkCorrect(b, strs[3]) }
func BenchmarkCorrectWith5Inputs(b *testing.B)  { benchmarkCorrect(b, strs[4]) }
func BenchmarkCorrectWith6Inputs(b *testing.B)  { benchmarkCorrect(b, strs[5]) }
func BenchmarkCorrectWith7Inputs(b *testing.B)  { benchmarkCorrect(b, strs[6]) }
func BenchmarkCorrectWith8Inputs(b *testing.B)  { benchmarkCorrect(b, strs[7]) }
func BenchmarkCorrectWith9Inputs(b *testing.B)  { benchmarkCorrect(b, strs[8]) }
func BenchmarkCorrectWith10Inputs(b *testing.B) { benchmarkCorrect(b, strs[9]) }
