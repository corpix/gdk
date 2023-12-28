package encoding

type EncodeDecoder interface {
	Encode([]byte) ([]byte, error)
	Decode([]byte) ([]byte, error)
}
