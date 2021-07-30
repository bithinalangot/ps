package ps

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/random"
)

// NewKeyPair creates a new PS signature signing key pair with private keys(x, y)
// which is scalar and public key (X, Y) which is a point on the curve G2.
func NewKeyPair(suite pairing.Suite, randoms []cipher.Stream) ([][]byte, [][]byte, error) {
	var PriKey [][]byte
	var PubKey [][]byte

	if len(randoms) < 2 {
		return nil, nil, fmt.Errorf("need minimum two random numbers")
	}

	for i := range randoms {
		Pkey, err := suite.G2().Scalar().Pick(randoms[i]).MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		PriKey = append(PriKey, Pkey)
	}

	for i := range PriKey {
		Pkey := suite.G1().Scalar()
		if err := Pkey.UnmarshalBinary(PriKey[i]); err != nil {
			return nil, nil, err
		}
		binPub, err := suite.G2().Point().Mul(Pkey, nil).MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		PubKey = append(PubKey, binPub)
	}

	return PriKey, PubKey, nil
}

// Sign creates a PS signature (h, h = h^(x+y*m)) on a given message msg using
// the private key priKey (x, y). The signature S is a pair of points on curve G1.
func Sign(suite pairing.Suite, priKey []kyber.Scalar, msg []byte) ([][]byte, error) {
	var S [][]byte
	h := suite.G1().Point().Pick(suite.RandomStream())
	binH, err := h.MarshalBinary()
	if err != nil {
		return nil, err
	}
	S = append(S, binH)

	y := suite.G1().Scalar().Mul(priKey[1], suite.G2().Scalar().SetBytes(msg))
	x := suite.G1().Scalar().Add(priKey[0], y)

	hX := suite.G1().Point().Mul(x, h)
	binHx, err := hX.MarshalBinary()
	if err != nil {
		return nil, err
	}
	S = append(S, binHx)

	return S, nil
}

// BatchSign creates a PS signature (h, h = h^(x + \Sigma_{i=1}^{r} y^m_r)) on a
// given set of messages using the private key priKey (x, y_1,...y_r). The
// signature S is a pair of points on the curve G1.
func BatchSign(suite pairing.Suite, priKey []kyber.Scalar, msgs [][]byte) ([][]byte, error) {
	var S [][]byte
	h := suite.G1().Point().Pick(suite.RandomStream())
	binH, err := h.MarshalBinary()
	if err != nil {
		return nil, err
	}
	S = append(S, binH)
	y := suite.G1().Scalar()

	for i, msg := range msgs {
		msgScalar := suite.G2().Scalar().SetBytes(msg)
		y.Add(y, suite.G1().Scalar().Mul(priKey[i+1], msgScalar))
	}
	x := suite.G1().Scalar().Add(priKey[0], y)
	hX := suite.G1().Point().Mul(x, h)
	binHx, err := hX.MarshalBinary()
	if err != nil {
		return nil, err
	}
	S = append(S, binHx)

	return S, nil
}

// AggreSign implements sequential aggregration of PS signatures
func AggreSign(suite pairing.Suite, priKey []kyber.Scalar, msg []byte) ([][]byte, error) {
	var S [][]byte
	t := suite.G1().Scalar().Pick(random.New())
	sigma1 := suite.G1().Point().Mul(t, nil)
	binSigma1, err := sigma1.MarshalBinary()
	if err != nil {
		return nil, err
	}
	S = append(S, binSigma1)

	msgScalar := suite.G2().Scalar().SetBytes(msg)
	y := suite.G1().Scalar().Mul(priKey[1], msgScalar)
	x := suite.G1().Scalar().Add(priKey[0], y)
	v := suite.G1().Scalar().Mul(x, t)
	sigma2 := suite.G1().Point().Mul(v, nil)
	binSigma2, err := sigma2.MarshalBinary()
	if err != nil {
		return nil, err
	}
	S = append(S, binSigma2)

	return S, nil
}

// Verify checks the given PS signature S on the message msg using the public
// key pubKey by verifying the equality e($\sigma_1$, X.Y^msg) == e($\sigma_2$, g)
func Verify(suite pairing.Suite, pubKey []kyber.Point, msg []byte, S [][]byte) error {
	msgScalar := suite.G2().Scalar().SetBytes(msg)

	Y := suite.G2().Point().Mul(msgScalar, pubKey[1])
	X := suite.G2().Point().Add(Y, pubKey[0])

	s1 := suite.G1().Point()
	if err := s1.UnmarshalBinary(S[0]); err != nil {
		return err
	}
	left := suite.Pair(s1, X)
	s2 := suite.G1().Point()
	if err := s2.UnmarshalBinary(S[1]); err != nil {
		return err
	}
	right := suite.Pair(s2, suite.G2().Point().Base())

	if !left.Equal(right) {
		return errors.New("ps: invalid signature")
	}

	return nil
}

// PSBatchVerify checks the given PS signature S on a set of messages using the public
// pubKey by verifying the equality e($\sigma_1$, X.\Sigma_{i=1}^r Y^m_i) == e($\sigma_2$, g)
func PSBatchVerify(suite pairing.Suite, pubKey []kyber.Point, msgs [][]byte, S [][]byte) error {
	Y := suite.G2().Point()

	for i, msg := range msgs {
		msgScalar := suite.G2().Scalar().SetBytes(msg)
		Y.Add(Y, suite.G2().Point().Mul(msgScalar, pubKey[i+1]))
	}
	X := suite.G2().Point().Add(Y, pubKey[0])

	s1 := suite.G1().Point()
	if err := s1.UnmarshalBinary(S[0]); err != nil {
		return err
	}
	left := suite.Pair(s1, X)

	s2 := suite.G1().Point()
	if err := s2.UnmarshalBinary(S[1]); err != nil {
		return err
	}
	right := suite.Pair(s2, suite.G2().Point().Base())

	if !left.Equal(right) {
		return errors.New("ps: invalid signature")
	}

	return nil
}

// Sequential aggregation where a signature S on a set of messages m_1,
// m_2,....,m_r, the Signature on message m_n can be sequentially aggregated
// S = (\sigma_1^t, (sigma_2 * sigma_1^(y * m)^t))
func AggregatePSSign(suite pairing.Suite, priKey kyber.Scalar, S [][]byte, msg []byte) ([][]byte, error) {
	var aggregateSign [][]byte

	t := suite.G1().Scalar().Pick(random.New())

	s1 := suite.G1().Point()
	if err := s1.UnmarshalBinary(S[0]); err != nil {
		return nil, err
	}
	// sigma_1^t
	binSigma1, err := suite.G1().Point().Mul(t, s1).MarshalBinary()
	if err != nil {
		return nil, err
	}
	aggregateSign = append(aggregateSign, binSigma1)

	msgScalar := suite.G2().Scalar().SetBytes(msg)
	// y * m
	y := suite.G1().Scalar().Mul(priKey, msgScalar)
	// sigma_1^(y * m)
	sigma_1 := suite.G1().Point().Mul(y, s1)
	// sigma_2 * sigma_1^(y * m)
	s2 := suite.G1().Point()
	if err := s2.UnmarshalBinary(S[1]); err != nil {
		return nil, err
	}
	sigma_2 := suite.G1().Point()
	sigma_2.Add(sigma_1, s2)
	binSigma2, err := suite.G1().Point().Mul(t, sigma_2).MarshalBinary()
	if err != nil {
		return nil, err
	}
	aggregateSign = append(aggregateSign, binSigma2)

	return aggregateSign, nil
}
