package gouxp

import (
	"crypto/cipher"
	"encoding/binary"
	"sync/atomic"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"

	"golang.org/x/crypto/chacha20poly1305"
)

type CryptCodec interface {
	Encrypt(src []byte) (dst []byte, err error)
	Decrypt(src []byte) (dst []byte, err error)
	SetKey(key []byte)
	SetReadNonce(nonce []byte)
	SetWriteNonce(nonce []byte)
}

var (
	InitCryptoKey   = []byte("0053A6F94C9FF24598EB3E91E4378ADD")
	InitCryptoNonce = []byte("0D74DB42A91077DEB3E91E43")
)

type CryptoNonce struct {
	data []byte
}

func (nonce *CryptoNonce) incr() {
	l := len(nonce.data)
	if l > 8 {
		l = 8
	}

	n := binary.LittleEndian.Uint64(nonce.data[:l])
	n++
	binary.LittleEndian.PutUint64(nonce.data[:l], n)
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
	if len(nonce) < chacha20poly1305.NonceSize {
		panic(ErrInvalidNonceSize)
	}

	cryptoNonce := nonceValue.Load().(*CryptoNonce)
	copy(cryptoNonce.data[:], nonce)
	nonceValue.Store(cryptoNonce)
}

func (codec *Chacha20poly1305Crypto) SetReadNonce(nonce []byte) {
	codec.setNonce(nonce, &codec.readNonce)
}

func (codec *Chacha20poly1305Crypto) SetWriteNonce(nonce []byte) {
	codec.setNonce(nonce, &codec.writeNonce)
}

// change data format |---MAC---|---DATA---| to |---DATA---|---MAC---|
func (codec *Chacha20poly1305Crypto) Encrypt(src []byte) (dst []byte, err error) {
	copy(src, src[codec.aead.Overhead():len(src)])
	nonce := codec.writeNonce.Load().(*CryptoNonce)
	dst = codec.aead.Seal(src[:0], nonce.data, src[:len(src)-codec.aead.Overhead()], nil)
	//nonce.incr()
	return
}

func (codec *Chacha20poly1305Crypto) Decrypt(src []byte) (dst []byte, err error) {
	nonce := codec.readNonce.Load().(*CryptoNonce)
	dst, err = codec.aead.Open(src[:0], nonce.data, src, nil)
	//nonce.incr()
	return
}

// In chacha20poly1305, data format is |---DATA---|---MAC---|
// In gouxp, data format is |---MAC---|---DATA---|
// When use chacha20poly1305, must modify data format to adapt chacha20poly1305.
// Chacha20poly1305 use 12bytes nonce
// In other way, you can use poly1305 + salsa20/chacha20 to avoid move origin data
func NewChacha20poly1305CryptoCodec() *Chacha20poly1305Crypto {
	codec := &Chacha20poly1305Crypto{}
	codec.readNonce.Store(&CryptoNonce{data: make([]byte, chacha20poly1305.NonceSize)})
	codec.writeNonce.Store(&CryptoNonce{data: make([]byte, chacha20poly1305.NonceSize)})
	codec.SetKey(InitCryptoKey)
	codec.SetReadNonce(InitCryptoNonce)
	codec.SetWriteNonce(InitCryptoNonce)

	aead, err := chacha20poly1305.New(codec.key[:])
	if err != nil {
		panic(err)
	}

	// IMPORTANT!
	// In gouxp, reserved MAC size is 16bytes in data head, so your encoder MUST use 16bytes MAC
	if aead.Overhead() < int(macSize) {
		panic("reserved mac size invalid")
	}

	codec.aead = aead
	return codec
}

var zeroValue atomic.Value

type Salsa20Crypto struct {
	enMacBuf      [macSize]byte // avoid make array every times
	deMacBuf      [macSize]byte
	key           [32]byte
	enPoly1305Key [32]byte
	dePoly1305Key [32]byte
	readNonce     atomic.Value
	writeNonce    atomic.Value
	nonceSize     int
}

func (codec *Salsa20Crypto) SetKey(key []byte) {
	copy(codec.key[:], key)
}

func (codec *Salsa20Crypto) setNonce(nonce []byte, nonceValue *atomic.Value) {
	if len(nonce) < codec.nonceSize {
		panic(ErrInvalidNonceSize)
	}

	cryptoNonce := nonceValue.Load().(*CryptoNonce)
	copy(cryptoNonce.data[:], nonce)
	nonceValue.Store(cryptoNonce)
}

func (codec *Salsa20Crypto) SetReadNonce(nonce []byte) {
	codec.setNonce(nonce, &codec.readNonce)
}

func (codec *Salsa20Crypto) SetWriteNonce(nonce []byte) {
	codec.setNonce(nonce, &codec.writeNonce)
}

// Salsa20 use 8 or 24bytes nonce, we choose 8bytes
func NewSalsa20CryptoCodec() *Salsa20Crypto {
	codec := &Salsa20Crypto{}
	codec.nonceSize = 8
	codec.readNonce.Store(&CryptoNonce{data: make([]byte, codec.nonceSize)})
	codec.writeNonce.Store(&CryptoNonce{data: make([]byte, codec.nonceSize)})
	codec.SetKey(InitCryptoKey)
	codec.SetReadNonce(InitCryptoNonce)
	codec.SetWriteNonce(InitCryptoNonce)
	return codec
}

func (codec *Salsa20Crypto) Encrypt(src []byte) (dst []byte, err error) {
	nonce := codec.writeNonce.Load().(*CryptoNonce)
	salsa20.XORKeyStream(src[macSize:], src[macSize:], nonce.data, &codec.key)

	salsa20.XORKeyStream(codec.enPoly1305Key[:], codec.enPoly1305Key[:], nonce.data, &codec.key)
	poly1305.Sum(&codec.enMacBuf, src[macSize:], &codec.enPoly1305Key)
	copy(src, codec.enMacBuf[:])

	zero := zeroValue.Load().([]byte)
	copy(codec.enPoly1305Key[:], zero)
	// nonce.incr()
	return src, nil
}

func (codec *Salsa20Crypto) Decrypt(src []byte) (dst []byte, err error) {
	nonce := codec.readNonce.Load().(*CryptoNonce)
	salsa20.XORKeyStream(codec.dePoly1305Key[:], codec.dePoly1305Key[:], nonce.data, &codec.key)
	copy(codec.deMacBuf[:], src[:macSize])

	if !poly1305.Verify(&codec.deMacBuf, src[macSize:], &codec.dePoly1305Key) {
		return nil, ErrMessageAuthFailed
	}

	salsa20.XORKeyStream(src[macSize:], src[macSize:], nonce.data, &codec.key)
	zero := zeroValue.Load().([]byte)
	copy(codec.dePoly1305Key[:], zero)
	// nonce.incr()
	return src[macSize:], nil
}

type CryptoType byte

const (
	UseChacha20 CryptoType = 0x05
	UseSalsa20  CryptoType = 0x06
)

func createCryptoCodec(tp CryptoType) CryptCodec {
	switch tp {
	case UseChacha20:
		return NewChacha20poly1305CryptoCodec()
	case UseSalsa20:
		return NewSalsa20CryptoCodec()
	default:
		return nil
	}
}

func init() {
	zero := make([]byte, 32)
	zeroValue.Store(zero)
}
