package govid

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"

	"github.com/dasio/base45"
)

func DecodeDigitalGreenCerificate(encodedDgc []byte) ([]byte, error) {
	if encodedDgc == nil {
		return nil, errors.New("No DGC was provided")
	}

	if encodedDgc[0] != 'H' || encodedDgc[1] != 'C' {
		return nil, errors.New("Malformed DGC")
	}
	i := 3
	for ; i < len(encodedDgc) && encodedDgc[i] != ':'; i++ {
	}
	if i == len(encodedDgc) {
		return nil, errors.New("Malformed DGC")
	}
	//version := encodedDgc[2:i]

	// strip the version prefix
	encodedDgc = encodedDgc[i+1:]

	// Decode from base45
	decodedDgc := make([]byte, base45.DecodedLen(len(encodedDgc)))
	base45.Decode(decodedDgc, encodedDgc)

	// decompress using zlib
	var dgc bytes.Buffer
	r, err := zlib.NewReader(bytes.NewBuffer(decodedDgc))
	if err != nil {
		return nil, err
	}
	io.Copy(&dgc, r)
	r.Close()

	return dgc.Bytes(), nil
}
