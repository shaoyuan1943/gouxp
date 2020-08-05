package gouxp

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync/atomic"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"

	"golang.org/x/crypto/chacha20poly1305"
)

type CryptoCodec interface {
	Encrypto(src []byte) (dst []byte, err error)
	Decrypto(src []byte) (dst []byte, err error)
	SetKey(key []byte)
	SetReadNonce(nonce []byte)
	SetWriteNonce(nonce []byte)
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
	nonce := codec.readNonce.Load().(*CryptoNonce)
	dst, err = codec.aead.Open(src[:0], nonce.data, src, nil)
	nonce.incr()
	return
}

// In chacha20poly1305, data format is |---DATA---|---MAC---|
// In gouxp, data format is |---MAC---|---DATA---|
// When use chacha20poly1305, must modify data format to adapt chacha20poly1305.
// Chacha20poly1305 use 24bytes nonce
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
	// In gouxp, reserved MAC size is 16bytes in data head, so your encoder MUST use 16bytes MAC
	if aead.Overhead() < int(macLen) {
		panic("reserved mac size invalid")
	}

	codec.aead = aead
	return codec
}

type Salsa20Crypto struct {
	enMacBuf      [macLen]byte
	deMacBuf      [macLen]byte
	key           [32]byte
	enPoly1305Key [32]byte
	dePoly1305Key [32]byte
	readNonce     atomic.Value
	writeNonce    atomic.Value
}

func (codec *Salsa20Crypto) SetKey(key []byte) {
	copy(codec.key[:], key)
}

func (codec *Salsa20Crypto) setNonce(nonce []byte, nonceValue *atomic.Value) {
	cryptoNonce := nonceValue.Load().(*CryptoNonce)
	cryptoNonce.data = make([]byte, 24)
	copy(cryptoNonce.data[:0], nonce)
	nonceValue.Store(cryptoNonce)
}

func (codec *Salsa20Crypto) SetReadNonce(nonce []byte) {
	codec.setNonce(nonce, &codec.readNonce)
}

func (codec *Salsa20Crypto) SetWriteNonce(nonce []byte) {
	codec.setNonce(nonce, &codec.writeNonce)
}

// Salsa20 use 8 or 24bytes nonce, we choose 24bytes
func NewSalsa20CryptoCodec() *Salsa20Crypto {
	codec := &Salsa20Crypto{}
	codec.readNonce.Store(&CryptoNonce{})
	codec.writeNonce.Store(&CryptoNonce{})
	codec.SetKey(initCryptoKey)
	codec.SetReadNonce(initCryptoNonce)
	codec.SetWriteNonce(initCryptoNonce)
	return codec
}

func (codec *Salsa20Crypto) Encrypto(src []byte) (dst []byte, err error) {
	nonce := codec.writeNonce.Load().(*CryptoNonce)
	salsa20.XORKeyStream(src[macLen:], src[macLen:], nonce.data, &codec.key)

	salsa20.XORKeyStream(codec.enPoly1305Key[:], codec.enPoly1305Key[:], nonce.data, &codec.key)
	poly1305.Sum(&codec.enMacBuf, src[macLen:], &codec.enPoly1305Key)
	copy(src, codec.enMacBuf[:])
	nonce.incr()
	return src, nil
}

func (codec *Salsa20Crypto) Decrypto(src []byte) (dst []byte, err error) {
	nonce := codec.readNonce.Load().(*CryptoNonce)
	salsa20.XORKeyStream(codec.dePoly1305Key[:], codec.dePoly1305Key[:], nonce.data, &codec.key)
	copy(codec.deMacBuf[:], src[:macLen])
	if !poly1305.Verify(&codec.deMacBuf, src[macLen:], &codec.dePoly1305Key) {
		return nil, errors.New("invalid data format")
	}

	salsa20.XORKeyStream(src[macLen:], src[macLen:], nonce.data, &codec.key)
	nonce.incr()
	return src[macLen:], nil
}

type CryptoType byte

const (
	UseChacha20poly1305 CryptoType = iota
	UseSalsa20
)

func CreateCryptoCodec(tp CryptoType) CryptoCodec {
	if tp == UseChacha20poly1305 {
		return NewChacha20poly1305CryptoCodec()
	} else if tp == UseSalsa20 {
		return NewSalsa20CryptoCodec()
	} else {
		panic("unknow crypto type.")
	}
}
