package encoding

import (
	"bytes"

	"github.com/klauspost/compress/zstd"
)

type EncodeDecoderZstd struct {
	*EncodeDecoderBase64
}

var _ EncodeDecoder = &EncodeDecoderZstd{}

//

func (e *EncodeDecoderZstd) Encode(buf []byte) ([]byte, error) {
	w := bytes.NewBuffer(nil)
	enc, err := zstd.NewWriter(w)
	if err != nil {
		return nil, err
	}
	defer enc.Close()
	_, err = enc.Write(buf)
	if err != nil {
		return nil, err
	}
	err = enc.Flush()
	if err != nil {
		return nil, err
	}
	return e.EncodeDecoderBase64.Encode(w.Bytes())
}

func (e *EncodeDecoderZstd) Decode(buf []byte) ([]byte, error) {
	w := bytes.NewBuffer(nil)
	decoder, err := zstd.NewReader(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()

	_, err = w.ReadFrom(decoder)
	if err != nil {
		return nil, err
	}
	return e.EncodeDecoderBase64.Decode(w.Bytes())
}

func NewEncodeDecoderZstd() *EncodeDecoderZstd {
	return &EncodeDecoderZstd{EncodeDecoderBase64: NewEncodeDecoderBase64()}
}
