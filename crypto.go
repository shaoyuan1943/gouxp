package gouxp

import (
	"encoding/binary"
	"golang.org/x/crypto/salsa20/salsa"
	"sync/atomic"
)

type Crypto interface {
	Encrypto(src, dst []byte) error
	Decrypto(src, dst []byte) error
}

var (
	codecKey   []byte = []byte("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D")
	codecNonce []byte = []byte("0D74DB42A91077DE")
)

type nonce struct {
	data [8]byte
}

func newNonce(data []byte) *nonce {
	no := &nonce{}
	copy(no.data[:], data)
	return no
}

func (no *nonce) incr() {
	n := binary.LittleEndian.Uint64(no.data[:])
	n++
	binary.LittleEndian.PutUint64(no.data[:], n)
}

func salsa20XORKeyStream(message []byte, key *[32]byte, nonce *[8]byte, blockCounter uint32) {
	var counter [16]byte
	for i := 0; i < 8; i++ {
		counter[i] = nonce[i]
	}

	binary.LittleEndian.PutUint32(counter[8:12], blockCounter)
	salsa.XORKeyStream(message, message, &counter, key)
}

type CryptoCodec struct {
	key        [32]byte
	readNonce  atomic.Value // [8]byte
	writeNonce atomic.Value // [8]byte
}

func (codec *CryptoCodec) setKey(key []byte) {
	copy(codec.key[:], key)
}

func (codec *CryptoCodec) setReadNonce(readNonce []byte) {
	no := codec.readNonce.Load().(*nonce)
	if no == nil {
		no = &nonce{}
	}
	copy(no.data[:], readNonce)
	codec.readNonce.Store(no)
}

func (codec *CryptoCodec) setWriteNonce(writeNonce []byte) {
	no := codec.writeNonce.Load().(*nonce)
	if no == nil {
		no = &nonce{}
	}
	copy(no.data[:], writeNonce)
	codec.writeNonce.Store(no)
}

func NewCryptoCodec() *CryptoCodec {
	codec := &CryptoCodec{}
	codec.setKey(codecKey)
	codec.setReadNonce(codecNonce)
	codec.setWriteNonce(codecNonce)
	return codec
}

// encode
func (codec *CryptoCodec) Encrypto(src, dst []byte) {
	nonce := codec.writeNonce.Load().(*nonce)
	salsa20XORKeyStream(src, &codec.key, &nonce.data, 1)
	nonce.incr()
}

func (codec *CryptoCodec) Decrypto(src, dst []byte) {
	nonce := codec.readNonce.Load().(*nonce)
	salsa20XORKeyStream(src, &codec.key, &nonce.data, 1)
	nonce.incr()
}
