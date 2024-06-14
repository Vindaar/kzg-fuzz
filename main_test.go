package fuzz

import (
	"math/rand"
	"os"
	"testing"

	gokzg "github.com/crate-crypto/go-kzg-4844"
	ckzg "github.com/ethereum/c-kzg-4844/bindings/go"
	ctt "github.com/mratsim/constantine/constantine-go"
	"github.com/stretchr/testify/require"
)

var gokzgCtx *gokzg.Context
var cttKzgCtx ctt.EthKzgContext

func TestMain(m *testing.M) {
	err := ckzg.LoadTrustedSetupFile("trusted_setup.txt")
	if err != nil {
		panic("Failed to load trusted setup")
	}
	gokzgCtx, err = gokzg.NewContext4096Secure()
	if err != nil {
		panic("Failed to create context")
	}

	cttKzgCtx, err = ctt.EthKzgContextNew("trusted_setup.txt")
	if err != nil {
		panic("Failed to create context or load trusted setup")
	}
	defer cttKzgCtx.Delete()


	code := m.Run()

	ckzg.FreeTrustedSetup()
	os.Exit(code)
}

///////////////////////////////////////////////////////////////////////////////
// Differential Fuzzing Functions
///////////////////////////////////////////////////////////////////////////////

func FuzzBlobToKZGCommitment(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64) {
		cKzgBlob, goKzgBlob, cttKzgBlob, ok := GetRandBlob(t, seed)
		if !ok {
			t.SkipNow()
		}

		cKzgCommitment, cKzgErr := ckzg.BlobToKZGCommitment(cKzgBlob)
		goKzgCommitment, goKzgErr := gokzgCtx.BlobToKZGCommitment(goKzgBlob, 1)
		cttKzgCommitment, cttKzgErr := cttKzgCtx.BlobToKzgCommitment(cttKzgBlob)

		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		require.Equal(t, cKzgErr == nil, cttKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil && cttKzgErr == nil {
			require.Equal(t, cKzgCommitment[:], goKzgCommitment[:])
			require.Equal(t, cttKzgCommitment[:], cttKzgCommitment[:])
		}
	})
}

func FuzzComputeKZGProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64) {
		cKzgBlob, goKzgBlob, cttKzgBlob, ok := GetRandBlob(t, seed)
		if !ok {
			t.SkipNow()
		}
		cKzgZ, goKzgZ, cttKzgZ, ok := GetRandFieldElement(t, seed)
		if !ok {
			t.SkipNow()
		}

		cKzgProof, cKzgY, cKzgErr := ckzg.ComputeKZGProof(cKzgBlob, cKzgZ)
		goKzgProof, goKzgY, goKzgErr := gokzgCtx.ComputeKZGProof(goKzgBlob, goKzgZ, 1)
		cttKzgProof, cttKzgY, cttKzgErr := cttKzgCtx.ComputeKzgProof(cttKzgBlob, cttKzgZ)

		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		require.Equal(t, cKzgErr == nil, cttKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil {
			require.Equal(t, cKzgProof[:], goKzgProof[:])
			require.Equal(t, cKzgY[:], goKzgY[:])
			require.Equal(t, cKzgProof[:], cttKzgProof[:])
			require.Equal(t, cKzgY[:], cttKzgY[:])
		}
	})
}

func FuzzComputeBlobKZGProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64) {
		cKzgBlob, goKzgBlob, cttKzgBlob, ok := GetRandBlob(t, seed)
		if !ok {
			t.SkipNow()
		}
		cKzgCommitment, goKzgCommitment, cttKzgCommitment, ok := GetRandCommitment(t, seed)
		if !ok {
			t.SkipNow()
		}

		cKzgProof, cKzgErr := ckzg.ComputeBlobKZGProof(cKzgBlob, cKzgCommitment)
		goKzgProof, goKzgErr := gokzgCtx.ComputeBlobKZGProof(goKzgBlob, goKzgCommitment, 1)
		cttKzgProof, cttKzgErr := cttKzgCtx.ComputeBlobKzgProof(cttKzgBlob, cttKzgCommitment)

		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		require.Equal(t, cKzgErr == nil, cttKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil && cttKzgErr == nil {
			require.Equal(t, cKzgProof[:], goKzgProof[:])
			require.Equal(t, cKzgProof[:], cttKzgProof[:])
		}
	})
}

func FuzzVerifyKZGProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64) {
		cKzgCommitment, goKzgCommitment, cttKzgCommitment, ok := GetRandCommitment(t, seed)
		if !ok {
			t.SkipNow()
		}
		cKzgZ, goKzgZ, cttKzgZ, ok := GetRandFieldElement(t, seed)
		if !ok {
			t.SkipNow()
		}
		cKzgY, goKzgY, cttKzgYCh, ok := GetRandFieldElement(t, seed)
		// Need to convert the ctt.EthKzgChallenge to the correct type returned by ctt.ComputeKzgProof
		var cttKzgY ctt.EthKzgEvalAtChallenge = ctt.EthKzgEvalAtChallenge(cttKzgYCh)
		if !ok {
			t.SkipNow()
		}
		cKzgProof, goKzgProof, cttKzgProof, ok := GetRandProof(t, seed)
		if !ok {
			t.SkipNow()
		}

		rand.Seed(seed)
		if seed%2 == 0 {
			var cKzgErr, goKzgErr error
			var cKzgProofTrusted ckzg.KZGProof

			// Generate a blob that'll be used to make a commitment/proof
			cKzgBlob, goKzgBlob, cttKzgBlob, ok := GetRandBlob(t, seed)
			if !ok {
				t.SkipNow()
			}

			// Generate a KZGCommitment to that blob
			cKzgCommitmentTrusted, cKzgErr := ckzg.BlobToKZGCommitment(cKzgBlob)
			cKzgCommitment = ckzg.Bytes48(cKzgCommitmentTrusted)
			goKzgCommitment, goKzgErr = gokzgCtx.BlobToKZGCommitment(goKzgBlob, 1)
			cttKzgCommitment, cttKzgErr := cttKzgCtx.BlobToKzgCommitment(cttKzgBlob)
			require.Equal(t, cKzgErr == nil, goKzgErr == nil)
			require.Equal(t, cKzgErr == nil, cttKzgErr == nil)
			if cKzgErr == nil && goKzgErr == nil && cttKzgErr == nil {
				require.Equal(t, cKzgCommitment[:], goKzgCommitment[:])
				require.Equal(t, cKzgCommitment[:], cttKzgCommitment[:])
			}

			// Generate a KZGProof to that blob/point
			cKzgProofTrusted, cKzgY, cKzgErr = ckzg.ComputeKZGProof(cKzgBlob, cKzgZ)
			cKzgProof = ckzg.Bytes48(cKzgProofTrusted)
			goKzgProof, goKzgY, goKzgErr = gokzgCtx.ComputeKZGProof(goKzgBlob, goKzgZ, 1)
			cttKzgProof, cttKzgY, cttKzgErr = cttKzgCtx.ComputeKzgProof(cttKzgBlob, cttKzgZ)
			require.Equal(t, cKzgErr == nil, goKzgErr == nil)
			require.Equal(t, cKzgErr == nil, cttKzgErr == nil)
			if cKzgErr == nil && goKzgErr == nil && cttKzgErr == nil {
				require.Equal(t, cKzgProof[:], goKzgProof[:])
				require.Equal(t, cKzgProof[:], cttKzgProof[:])
			}
		}

		cKzgResult, cKzgErr := ckzg.VerifyKZGProof(cKzgCommitment, cKzgZ, cKzgY, cKzgProof)
		goKzgErr := gokzgCtx.VerifyKZGProof(goKzgCommitment, goKzgZ, goKzgY, goKzgProof)
		goKzgResult := goKzgErr == nil
		cttKzgResult, cttKzgErr := cttKzgCtx.VerifyKzgProof(cttKzgCommitment, cttKzgZ, cttKzgY, cttKzgProof)

		t.Logf("go-kzg error: %v\n", cKzgErr)
		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		require.Equal(t, cKzgErr == nil, cttKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil && cttKzgErr == nil {
			require.Equal(t, cKzgResult, goKzgResult)
			require.Equal(t, cKzgResult, cttKzgResult)
		}
	})
}

func FuzzVerifyBlobKZGProofSingle(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64) {
		cKzgBlob, goKzgBlob, cttKzgBlob, ok := GetRandBlob(t, seed)
		if !ok {
			t.SkipNow()
		}
		cKzgCommitment, goKzgCommitment, cttKzgCommitment, ok := GetRandCommitment(t, seed)
		if !ok {
			t.SkipNow()
		}
		cKzgProof, goKzgProof, cttKzgProof, ok := GetRandProof(t, seed)
		if !ok {
			t.SkipNow()
		}

		if seed%2 == 0 {
			var cKzgErr, goKzgErr, cttKzgErr error
			var cKzgProofTrusted ckzg.KZGProof

			// Generate a KZGProof to that blob/commitment
			cKzgProofTrusted, cKzgErr = ckzg.ComputeBlobKZGProof(cKzgBlob, cKzgCommitment)
			cKzgProof = ckzg.Bytes48(cKzgProofTrusted)
			goKzgProof, goKzgErr = gokzgCtx.ComputeBlobKZGProof(goKzgBlob, goKzgCommitment, 1)
			cttKzgProof, cttKzgErr = cttKzgCtx.ComputeBlobKzgProof(cttKzgBlob, cttKzgCommitment)
			require.Equal(t, cKzgErr == nil, goKzgErr == nil)
			require.Equal(t, cKzgErr == nil, cttKzgErr == nil)
			if cKzgErr == nil && goKzgErr == nil && cttKzgErr == nil {
				require.Equal(t, cKzgProof[:], goKzgProof[:])
				require.Equal(t, cKzgProof[:], cttKzgProof[:])
			}
		}

		cKzgResult, cKzgErr := ckzg.VerifyBlobKZGProof(cKzgBlob, cKzgCommitment, cKzgProof)
		goKzgErr := gokzgCtx.VerifyBlobKZGProof(goKzgBlob, goKzgCommitment, goKzgProof)
		goKzgResult := goKzgErr == nil
		cttKzgResult, cttKzgErr := cttKzgCtx.VerifyBlobKzgProof(cttKzgBlob, cttKzgCommitment, cttKzgProof)


		t.Logf("go-kzg error: %v\n", cKzgErr)
		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		require.Equal(t, cKzgErr == nil, cttKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil && cttKzgErr == nil {
			require.Equal(t, cKzgResult, goKzgResult)
			require.Equal(t, cKzgResult, cttKzgResult)
		}
	})
}

func FuzzVerifyBlobKZGProofBatch(f *testing.F) {
	// Generate a single set of random bytes for constantine's batch verify
	var secureRandomBytes [32]byte
	_, _ = rand.Read(secureRandomBytes[:])

	f.Fuzz(func(t *testing.T, seed int64) {

		// Between 1 and 5, inclusive
		count := (rand.Uint64() % 5) + 1

		cKzgBlobs := make([]ckzg.Blob, count)
		cKzgCommitments := make([]ckzg.Bytes48, count)
		cKzgProofs := make([]ckzg.Bytes48, count)
		goKzgBlobs := make([]gokzg.Blob, count)
		goKzgCommitments := make([]gokzg.KZGCommitment, count)
		goKzgProofs := make([]gokzg.KZGProof, count)
		cttKzgBlobs := make([]ctt.EthBlob, count)
		cttKzgCommitments := make([]ctt.EthKzgCommitment, count)
		cttKzgProofs := make([]ctt.EthKzgProof, count)

		for i := 0; i < int(count); i++ {
			var cKzgBlob ckzg.Blob
			var cKzgCommitment ckzg.Bytes48
			var cKzgProof ckzg.Bytes48
			var goKzgBlob gokzg.Blob
			var goKzgCommitment gokzg.KZGCommitment
			var goKzgProof gokzg.KZGProof
			var cttKzgBlob ctt.EthBlob
			var cttKzgCommitment ctt.EthKzgCommitment
			var cttKzgProof ctt.EthKzgProof

			completelyRandom := rand.Intn(2) != 0
			if completelyRandom {
				var ok bool
				cKzgBlob, goKzgBlob, cttKzgBlob, ok = GetRandBlob(t, seed)
				if !ok {
					t.SkipNow()
				}
				cKzgCommitment, goKzgCommitment, cttKzgCommitment, ok = GetRandCommitment(t, seed)
				if !ok {
					t.SkipNow()
				}
				cKzgProof, goKzgProof, cttKzgProof, ok = GetRandProof(t, seed)
				if !ok {
					t.SkipNow()
				}
			} else {
				var cKzgErr, goKzgErr, cttKzgErr error
				var cKzgProofTrusted ckzg.KZGProof

				// Generate a KZGProof to that blob/commitment
				cKzgProofTrusted, cKzgErr = ckzg.ComputeBlobKZGProof(cKzgBlob, cKzgCommitment)
				cKzgProof = ckzg.Bytes48(cKzgProofTrusted)
				goKzgProof, goKzgErr = gokzgCtx.ComputeBlobKZGProof(goKzgBlob, goKzgCommitment, 1)
				cttKzgProof, cttKzgErr = cttKzgCtx.ComputeBlobKzgProof(cttKzgBlob, cttKzgCommitment)
				require.Equal(t, cKzgErr == nil, goKzgErr == nil)
				require.Equal(t, cKzgErr == nil, cttKzgErr == nil)
				if cKzgErr == nil && goKzgErr == nil && cttKzgErr == nil {
					require.Equal(t, cKzgProof[:], goKzgProof[:])
					require.Equal(t, cKzgProof[:], cttKzgProof[:])
				}
			}

			cKzgBlobs[i] = cKzgBlob
			cKzgCommitments[i] = cKzgCommitment
			cKzgProofs[i] = cKzgProof

			goKzgBlobs[i] = goKzgBlob
			goKzgCommitments[i] = goKzgCommitment
			goKzgProofs[i] = goKzgProof

			cttKzgBlobs[i] = cttKzgBlob
			cttKzgCommitments[i] = cttKzgCommitment
			cttKzgProofs[i] = cttKzgProof
		}

		cKzgResult, cKzgErr := ckzg.VerifyBlobKZGProofBatch(cKzgBlobs, cKzgCommitments, cKzgProofs)
		goKzgErr := gokzgCtx.VerifyBlobKZGProofBatch(goKzgBlobs, goKzgCommitments, goKzgProofs)
		goKzgResult := goKzgErr == nil
		cttKzgResult, cttKzgErr := cttKzgCtx.VerifyBlobKzgProofBatch(cttKzgBlobs, cttKzgCommitments, cttKzgProofs, secureRandomBytes)

		t.Logf("go-kzg error: %v\n", cKzgErr)
		require.Equal(t, cKzgErr == nil, goKzgErr == nil)
		require.Equal(t, cKzgErr == nil, cttKzgErr == nil)
		if cKzgErr == nil && goKzgErr == nil && cttKzgErr == nil {
			require.Equal(t, cKzgResult, goKzgResult)
			require.Equal(t, cKzgResult, cttKzgResult)
		}
	})
}
