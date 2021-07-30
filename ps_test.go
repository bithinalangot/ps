package ps

import (
	"crypto/cipher"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestPS(t *testing.T) {
	var randoms []cipher.Stream
	msg := []byte("Hello PS Signature")
	suite := pairing.NewSuiteBn256()
	r := 2

	for i := 0; i < r; i++ {
		randoms = append(randoms, random.New())
	}
	private, public, err := NewKeyPair(suite, randoms)
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	err = Verify(suite, public, msg, sig)
	require.Nil(t, err)
}

func TestPSFailSig(t *testing.T) {
	var randoms []cipher.Stream
	msg := []byte("Hello PS Signature")
	suite := pairing.NewSuiteBn256()
	r := 2

	for i := 0; i < r; i++ {
		randoms = append(randoms, random.New())
	}
	private, public, err := NewKeyPair(suite, randoms)
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	sig[0][0] ^= 0x01
	if Verify(suite, public, msg, sig) == nil {
		t.Fatal("ps: verification succeeded unexpectedly")
	}
}

func TestBatchPSSig(t *testing.T) {
	suite := pairing.NewSuiteBn256()
	r := 4
	var randoms2 []cipher.Stream
	var msgs [][]byte

	for i := 0; i < r; i++ {
		randoms2 = append(randoms2, random.New())
	}
	BpriKey, BpubKey, err := NewKeyPair(suite, randoms2)

	if err != nil {
		t.Fatal("Key generation not successful!")
	}

	for j := 1; j < r-1; j++ {
		msgs = append(msgs, []byte("PS Batch Verify "+strconv.Itoa(j)))
	}

	sig, err := BatchSign(suite, BpriKey[:len(BpriKey)-1], msgs)
	require.Nil(t, err)
	err = PSBatchVerify(suite, BpubKey, msgs, sig)
	require.Nil(t, err)
}

func TestBatchPSFailSig(t *testing.T) {
	suite := pairing.NewSuiteBn256()
	r := 4
	var randoms2 []cipher.Stream
	var msgs [][]byte

	for i := 0; i < r; i++ {
		randoms2 = append(randoms2, random.New())
	}
	BpriKey, BpubKey, err := NewKeyPair(suite, randoms2)

	if err != nil {
		t.Fatal("Key generation not successful!")
	}

	for j := 1; j < r-1; j++ {
		msgs = append(msgs, []byte("PS Batch Verify "+strconv.Itoa(j)))
	}

	sig, err := BatchSign(suite, BpriKey[:len(BpriKey)-1], msgs)
	require.Nil(t, err)
	sig[0][0] ^= 0x01
	if PSBatchVerify(suite, BpubKey, msgs, sig) == nil {
		t.Fatal("ps: batch verification succeeded unexpectedly")
	}
}

func TestAggregatePSSign(t *testing.T) {
	suite := pairing.NewSuiteBn256()
	r := 4
	var randoms []cipher.Stream
	var aggreMsg [][]byte

	msg1 := []byte("PS Aggregate verify 1")
	msg2 := []byte("PS Aggregate verify 2")
	aggreMsg = append(aggreMsg, msg1)
	aggreMsg = append(aggreMsg, msg2)

	for i := 0; i < r; i++ {
		randoms = append(randoms, random.New())
	}
	AggrpriKey, AggrpubKey, err := NewKeyPair(suite, randoms)

	if err != nil {
		t.Fatal("Key generation not successful!")
	}

	AS, err := AggreSign(suite, AggrpriKey, aggreMsg[0])
	require.Nil(t, err)

	msg3 := []byte("PS Aggregate verify 3")
	aggreMsg = append(aggreMsg, msg3)

	AS1, err := AggregatePSSign(suite, AggrpriKey[2], AS, aggreMsg[1])
	require.Nil(t, err)
	AS2, err := AggregatePSSign(suite, AggrpriKey[3], AS1, aggreMsg[2])
	require.Nil(t, err)

	err = PSBatchVerify(suite, AggrpubKey, aggreMsg, AS2)
	require.Nil(t, err)
}

func TestAggregatePSFailSign(t *testing.T) {
	suite := pairing.NewSuiteBn256()
	r := 4
	var randoms []cipher.Stream
	var aggreMsg [][]byte

	msg1 := []byte("PS Aggregate verify 1")
	msg2 := []byte("PS Aggregate verify 2")
	aggreMsg = append(aggreMsg, msg1)
	aggreMsg = append(aggreMsg, msg2)

	for i := 0; i < r; i++ {
		randoms = append(randoms, random.New())
	}
	AggrpriKey, AggrpubKey, err := NewKeyPair(suite, randoms)

	if err != nil {
		t.Fatal("Key generation not successful!")
	}

	AS, err := AggreSign(suite, AggrpriKey, aggreMsg[0])
	require.Nil(t, err)

	msg3 := []byte("PS Aggregate verify 3")
	aggreMsg = append(aggreMsg, msg3)

	AS1, err := AggregatePSSign(suite, AggrpriKey[2], AS, aggreMsg[1])
	require.Nil(t, err)
	AS2, err := AggregatePSSign(suite, AggrpriKey[3], AS1, aggreMsg[2])
	require.Nil(t, err)

	AS2[0][1] ^= 0x01

	if PSBatchVerify(suite, AggrpubKey, aggreMsg, AS2) == nil {
		t.Fatal("ps: aggregate verification succeeded unexpectedly")
	}
}

func BenchmarkPSKeyCreation(b *testing.B) {
	var randoms []cipher.Stream
	suite := pairing.NewSuiteBn256()
	r := 2

	for i := 0; i < r; i++ {
		randoms = append(randoms, random.New())
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewKeyPair(suite, randoms)
	}
}

func BenchmarkPSSign(b *testing.B) {
	var randoms []cipher.Stream
	suite := pairing.NewSuiteBn256()
	r := 2
	for i := 0; i < r; i++ {
		randoms = append(randoms, random.New())
	}
	private, _, _ := NewKeyPair(suite, randoms)
	msg := []byte("Hello PS Signature")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(suite, private, msg)
	}
}

func BenchmarkPSVerify(b *testing.B) {
	var randoms []cipher.Stream
	msg := []byte("Hello PS Signature")
	suite := pairing.NewSuiteBn256()
	r := 2

	for i := 0; i < r; i++ {
		randoms = append(randoms, random.New())
	}
	private, public, _ := NewKeyPair(suite, randoms)
	sig, _ := Sign(suite, private, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(suite, public, msg, sig)
	}
}

func BenchmarkPSBatchSign(b *testing.B) {
	suite := pairing.NewSuiteBn256()
	r := 101
	var randoms2 []cipher.Stream
	var msgs [][]byte

	for i := 0; i < r; i++ {
		randoms2 = append(randoms2, random.New())
	}
	BpriKey, _, _ := NewKeyPair(suite, randoms2)

	for j := 1; j < r-1; j++ {
		msgs = append(msgs, []byte("PS Batch Verify "+strconv.Itoa(j)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BatchSign(suite, BpriKey[:len(BpriKey)-1], msgs)
	}
}

func BenchmarkPSBatchVerify(b *testing.B) {
	suite := pairing.NewSuiteBn256()
	r := 3
	var randoms2 []cipher.Stream
	var msgs [][]byte

	for i := 0; i < r; i++ {
		randoms2 = append(randoms2, random.New())
	}
	BpriKey, BpubKey, _ := NewKeyPair(suite, randoms2)
	for j := 1; j < r-1; j++ {
		msgs = append(msgs, []byte("PS Batch Verify "+strconv.Itoa(j)))
	}

	sig, _ := BatchSign(suite, BpriKey[:len(BpriKey)-1], msgs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PSBatchVerify(suite, BpubKey, msgs, sig)
	}
}

func BenchmarkAggregatePSSign(b *testing.B) {
	suite := pairing.NewSuiteBn256()
	r := 4
	var randoms []cipher.Stream
	var aggreMsg [][]byte

	msg1 := []byte("PS Aggregate verify 1")
	msg2 := []byte("PS Aggregate verify 2")
	msg3 := []byte("PS Aggregate verify 3")
	aggreMsg = append(aggreMsg, msg1)
	aggreMsg = append(aggreMsg, msg2)
	aggreMsg = append(aggreMsg, msg3)

	for i := 0; i < r; i++ {
		randoms = append(randoms, random.New())
	}
	AggrpriKey, _, _ := NewKeyPair(suite, randoms)
	AS, _ := AggreSign(suite, AggrpriKey, aggreMsg[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AS1, _ := AggregatePSSign(suite, AggrpriKey[2], AS, aggreMsg[1])
		_, _ = AggregatePSSign(suite, AggrpriKey[3], AS1, aggreMsg[2])
	}
}

func BenchmarkAggregatePSVerify(b *testing.B) {
	suite := pairing.NewSuiteBn256()
	r := 4
	var randoms []cipher.Stream
	var aggreMsg [][]byte

	msg1 := []byte("PS Aggregate verify 1")
	msg2 := []byte("PS Aggregate verify 2")
	msg3 := []byte("PS Aggregate verify 3")
	aggreMsg = append(aggreMsg, msg1)
	aggreMsg = append(aggreMsg, msg2)
	aggreMsg = append(aggreMsg, msg3)

	for i := 0; i < r; i++ {
		randoms = append(randoms, random.New())
	}
	AggrpriKey, AggrpubKey, _ := NewKeyPair(suite, randoms)

	AS, _ := AggreSign(suite, AggrpriKey, aggreMsg[0])

	AS1, _ := AggregatePSSign(suite, AggrpriKey[2], AS, aggreMsg[1])
	AS2, _ := AggregatePSSign(suite, AggrpriKey[3], AS1, aggreMsg[2])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PSBatchVerify(suite, AggrpubKey, aggreMsg, AS2)
	}
}
