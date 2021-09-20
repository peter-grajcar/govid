package main

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/peter-grajcar/govid"
)

func loadPublicKey(path string) (crypto.PublicKey, error) {
	pubKeyPem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pubKeyPem)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	return pubKey, err
}

func handleError(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	encodedDgc, err := ioutil.ReadAll(os.Stdin)
	handleError(err)

	pubKey, err := loadPublicKey("samples/sk.pem")
	handleError(err)

	dgc, err := govid.DecodeDigitalGreenCerificate(encodedDgc)
	handleError(err)

	structure, err := govid.UnmarshalCoseStructure(dgc)
	handleError(err)

	header, err := structure.UnmarshalHeader()
	handleError(err)

	claims, err := structure.UnmarshalPayload()
	handleError(err)

	valid := structure.Verify(pubKey, crypto.SHA256)

	fmt.Printf("Valid: %t\n", valid)
	fmt.Printf("Algorithm: %d\n", header.Algorithm)
	fmt.Printf("Key ID: %s\n", base64.StdEncoding.EncodeToString(header.KeyId))
	fmt.Printf("Signature: %x\n", structure.Signature)
	fmt.Println("Payload:")
	fmt.Println("  Issuer:", claims.Issuer)
	fmt.Println("  Issued At:", time.Unix(int64(claims.IssuedAt), 0).Format("2006-01-02"))
	fmt.Println("  Expiring Date:", time.Unix(int64(claims.ExpiringDate), 0).Format("2006-01-02"))
	fmt.Println("  Certificate:")
	for key, val := range claims.HealthCertificate[1].(map[interface{}]interface{}) {
		fmt.Printf("    %s: %s\n", key, val)
	}
}
