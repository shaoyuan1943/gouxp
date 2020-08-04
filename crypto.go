package gouxp

import (
	"crypto/cipher"
	"encoding/binary"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

type Crypto interface {
	Encrypto(src []byte) (dst []byte, err error)
	Decrypto(src []byte) (dst []byte, err error)
}

var (
	initCryptoKey   = []byte("0053A6F94C9FF24598EB3E91E4378ADD")
	initCryptoNonce = []byte("0D74DB42A91077DEB3E91E43")
)

type CryptoNonce struct {
	data []byte
}

func (cn *CryptoNonce) incr() {
	l := len(cn.data)
	if l > 8 {
		l = 8
	}

	n := binary.LittleEndian.Uint64(cn.data[:l])
	n++
	binary.LittleEndian.PutUint64(cn.data[:l], n)
}

type Chacha20poly1305Crypto struct {
	aead       cipher.AEAD
	key        [32]byte
	readNonce  atomic.Value
	writeNonce atomic.Value
}

func (codec *Chacha20poly1305Crypto) SetKey(key []byte) {
	copy(codec.key[:], key)
}

func (codec *Chacha20poly1305Crypto) setNonce(nonce []byte, nonceValue *atomic.Value) {
	cryptoNonce := nonceValue.Load().(*CryptoNonce)
	cryptoNonce.data = make([]byte, chacha20poly1305.NonceSize)
	copy(cryptoNonce.data[:0], nonce)
	nonceValue.Store(cryptoNonce)
}

func (codec *Chacha20poly1305Crypto) SetReadNonce(nonce []byte) {
	codec.setNonce(nonce, &codec.readNonce)
}

func (codec *Chacha20poly1305Crypto) SetWriteNonce(nonce []byte) {
	codec.setNonce(nonce, &codec.writeNonce)
}

// change data format |---MAC---|---DATA---| to |---DATA---|---MAC---|
func (codec *Chacha20poly1305Crypto) Encrypto(src []byte) (dst []byte, err error) {
	copy(src, src[codec.aead.Overhead():len(src)])
	nonce := codec.writeNonce.Load().(*CryptoNonce)
	dst = codec.aead.Seal(src[:0], nonce.data, src[:len(src)-codec.aead.Overhead()], nil)
	nonce.incr()
	return
}

func (codec *Chacha20poly1305Crypto) Decrypto(src []byte) (dst []byte, err error) {
	reserveN := int(macLen)
	contentN := len(src) - reserveN
	reserveBuffer := make([]byte, reserveN)
	copy(reserveBuffer, src[:reserveN])
	content := src[reserveN:len(src)]
	copy(src, content)
	copy(src[contentN:], reserveBuffer)

	nonce := codec.readNonce.Load().(*CryptoNonce)
	dst, err = codec.aead.Open(src[:0], nonce.data, src, nil)
	nonce.incr()
	return
}

// In chacha20poly1305, data format is |---DATA---|---MAC---|
// In gouxp, data format is |---MAC---|---DATA---|
// When use chacha20poly1305, must move data forward to adapt chacha20poly1305.
// In other way, you can use poly1305 + salsa20/chacha20 to avoid move origin data
func NewChacha20poly1305CryptoCodec() *Chacha20poly1305Crypto {
	codec := &Chacha20poly1305Crypto{}
	codec.readNonce.Store(&CryptoNonce{})
	codec.writeNonce.Store(&CryptoNonce{})
	codec.SetKey(initCryptoKey)
	codec.SetReadNonce(initCryptoNonce)
	codec.SetWriteNonce(initCryptoNonce)

	aead, err := chacha20poly1305.New(codec.key[:])
	if err != nil {
		panic(err)
	}

	// Important!
	// In gouxp, reserved MAC size is 16bytes, so your encoder MUST use 16bytes MAC
	if aead.Overhead() < int(macLen) {
		panic("reserved mac size invalid")
	}

	codec.aead = aead
	return codec
}
