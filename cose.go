package govid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"reflect"

	"github.com/fxamacker/cbor"
)

type CoseHeader struct {
	Algorithm int    `cbor:"1,keyasint,omitempty"`
	KeyId     []byte `cbor:"4,keyasint,omitempty"`
}

type CoseClaims struct {
	Issuer            string              `cbor:"1,keyasint,omitempty"`
	IssuedAt          uint                `cbor:"6,keyasint,omitempty"`
	ExpiringDate      uint                `cbor:"4,keyasint,omitempty"`
	HealthCertificate map[int]interface{} `cbor:"-260,keyasint,omitempty"`
}

type CoseStructure struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected interface{}
	Payload     []byte
	Signature   []byte
}

func (cose *CoseStructure) ToBeSigned(external []byte) []byte {
	sigStructure := []interface{}{
		"Signature1",
		cose.Protected,
		external,
		cose.Payload,
	}
	toBeSigned, _ := cbor.Marshal(sigStructure, cbor.CanonicalEncOptions())
	return toBeSigned
}

func (cose *CoseStructure) Verify(publicKey crypto.PublicKey, hash crypto.Hash) bool {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		hashFunc := hash.HashFunc().New()
		external := []byte{}
		hashFunc.Write(cose.ToBeSigned(external))
		digest := hashFunc.Sum(nil)

		privateKeyCurveBitSize := elliptic.P256().Params().BitSize
		publicKeyCurveBitSize := key.Curve.Params().BitSize

		if privateKeyCurveBitSize != publicKeyCurveBitSize {
			return false
		}

		keyCurveBytes := publicKeyCurveBitSize / 8

		r := big.NewInt(0).SetBytes(cose.Signature[:keyCurveBytes])
		s := big.NewInt(0).SetBytes(cose.Signature[keyCurveBytes:])

		return ecdsa.Verify(key, digest, r, s)
	default:
		fmt.Printf("Unimplemented public key algorithm: %s\n", reflect.TypeOf(key))
		return false
	}
}

func (cose *CoseStructure) UnmarshalHeader() (*CoseHeader, error) {
	header := &CoseHeader{}
	err := cbor.Unmarshal(cose.Protected, header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func (cose *CoseStructure) UnmarshalPayload() (*CoseClaims, error) {
	claims := &CoseClaims{}
	err := cbor.Unmarshal(cose.Payload, claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func UnmarshalCoseStructure(cert []byte) (*CoseStructure, error) {
	structure := &CoseStructure{}
	err := cbor.Unmarshal(cert, structure)
	if err != nil {
		return nil, err
	}
	return structure, nil
}
