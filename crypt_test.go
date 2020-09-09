package gouxp

import (
	"encoding/binary"
	"testing"

	"github.com/shaoyuan1943/gouxp/dh64"
)

var macLen = 16

func checkCrypto(t *testing.T, codec CryptoCodec, data []byte) bool {
	encryptoed, err := codec.Encrypto(data)
	if err != nil {
		t.Fatalf("codec.Encrypto err: %v\n", err)
		return false
	}
	t.Logf("encryptoed: %v\n", string(encryptoed))

	plaintext, err := codec.Decrypto(encryptoed)
	if err != nil {
		t.Fatalf("codec.Decrypto err: %v\n", err)
		return false
	}

	t.Logf("%v\n", string(plaintext))
	return true
}

func testCodec(t *testing.T, codec CryptoCodec) {
	for i := 0; i < 10; i++ {
		data := []byte("afdoiru43098hfjasd'optieoprifsadfr3efvedvte")
		testData := make([]byte, len(data)+int(macLen))
		copy(testData[macLen:], data)
		if checkCrypto(t, codec, testData) {
			t.Logf("%s\n", data)
		}

		data = []byte("5478432967489fnsadfjkasdkfwfdsfasdf234tr3453534534fde")
		testData = make([]byte, len(data)+int(macLen))
		copy(testData[macLen:], data)
		if checkCrypto(t, codec, testData) {
			t.Logf("%s\n", data)
		}

		data = []byte("wfmn;oi3kuhr48932yfhsadjhfvckjdsahfjdsf[3fasdfas'f;sad'f")
		testData = make([]byte, len(data)+int(macLen))
		copy(testData[macLen:], data)
		if checkCrypto(t, codec, testData) {
			t.Logf("%s\n", data)
		}

		data = []byte("f43n8ofy43p8fh3p8haisdhf80941ho;iasjhnifoahwe")
		testData = make([]byte, len(data)+int(macLen))
		copy(testData[macLen:], data)
		if checkCrypto(t, codec, testData) {
			t.Logf("%s\n", data)
		}

		data = []byte("fnpo34hp84h34f8hweafhcnaskljcfidsjdcf0j4-89jh4h3noihjkhj5ipo234u859-23y49p8r34")
		testData = make([]byte, len(data)+int(macLen))
		copy(testData[macLen:], data)
		if checkCrypto(t, codec, testData) {
			t.Logf("%s\n", data)
		}

		data = []byte("sdnajfhnoui324-hjfo[eqwihui324hf835498248fbjwadefbrwqekf-30ef=-[]f[]sdfsdfbu43i74fgs[w0re")
		testData = make([]byte, len(data)+int(macLen))
		copy(testData[macLen:], data)
		if checkCrypto(t, codec, testData) {
			t.Logf("%s\n", data)
		}

		data = []byte("fsd34809f43-2fhsdioafhio324h8r1h43fh4389hf9843hf8hsadiofhafh842391h348")
		testData = make([]byte, len(data)+int(macLen))
		copy(testData[macLen:], data)
		if checkCrypto(t, codec, testData) {
			t.Logf("%s\n", data)
		}
	}
}

func TestCryptoCodec(t *testing.T) {
	codec := createCryptoCodec(UseSalsa20)
	testCodec(t, codec)
}

func testErrorCrypto(t *testing.T, codec CryptoCodec) {
	data := []byte("f43n8ofy43p8fh3p8haisdhf80941ho;iasjhnifoahwe")
	myData := make([]byte, len(data)+int(macLen))
	copy(myData[macLen:], data)

	encryptoed, err := codec.Encrypto(myData)
	if err != nil {
		t.Fatalf("salsa20Codec.Encrypto err: %v\n", err)
		return
	}

	encryptoed[18] = 'Y'
	plaintext, err := codec.Decrypto(encryptoed)
	if err != nil {
		t.Fatalf("salsa20Codec.Decrypto err: %v\n", err)
		return
	}

	t.Logf("%v\n", string(plaintext))
}

func TestErrorCrypto(t *testing.T) {
	//salsa20Codec := CreateCryptoCodec(UseSalsa20)
	//testErrorCrypto(t, salsa20Codec)

	chacha20Codec := createCryptoCodec(UseChacha20)
	testErrorCrypto(t, chacha20Codec)
}

func TestTwoCodec(t *testing.T) {
	codec1 := createCryptoCodec(UseSalsa20)
	codec2 := createCryptoCodec(UseSalsa20)

	data := []byte("sdnajfhnoui324-hjfo[eqwihui324hf835498248fbjwadefbrwqekf-30ef=-[]f[]sdfsdfbu43i74fgs[w0re")
	testData := make([]byte, len(data)+int(macLen))
	copy(testData[macLen:], data)

	t.Logf("testData: %v", testData)
	cipherData, err := codec1.Encrypto(testData)
	if err != nil {
		t.Fatalf("encrypto err: %v", err)
		return
	}
	t.Logf("cipherData: %v", cipherData)
	plaintextData, err := codec2.Decrypto(cipherData)
	if err != nil {
		t.Fatalf("Decrypto err: %v", err)
		return
	}

	t.Logf("plaintextData: %v", plaintextData)
}

func TestClientServerCodec(t *testing.T) {
	clientCodec := createCryptoCodec(UseSalsa20)
	privateKey, publicKey := dh64.KeyPair()
	clientData := make([]byte, macLen+8)
	binary.LittleEndian.PutUint64(clientData[macLen:], publicKey)
	clientCipherData, err := clientCodec.Encrypto(clientData)
	if err != nil {
		t.Fatalf("clientCodec.Encrypto err: %v", err)
		return
	}

	serverCodec := createCryptoCodec(UseSalsa20)
	plaintextData, err := serverCodec.Decrypto(clientCipherData)
	if err != nil {
		t.Fatalf("serverCodec.Decrypto err: %v", err)
		return
	}

	clientPublicKey := binary.LittleEndian.Uint64(plaintextData)
	serverPrivateKey, serverPublicKey := dh64.KeyPair()
	serverNum := dh64.Secret(serverPrivateKey, clientPublicKey)
	var serverNonce [8]byte
	binary.LittleEndian.PutUint64(serverNonce[:], serverNum)

	serverData := make([]byte, macLen+16)
	binary.LittleEndian.PutUint64(serverData[macLen:], serverPublicKey)
	serverCipherData, err := serverCodec.Encrypto(serverData)
	if err != nil {
		t.Fatalf("serverCodec.Encrypto err: %v", err)
		return
	}

	serverCodec.SetReadNonce(serverNonce[:])
	serverCodec.SetWriteNonce(serverNonce[:])

	serverPlaintextData, err := clientCodec.Decrypto(serverCipherData)
	if err != nil {
		t.Fatalf("clientCodec.Decrypto err: %v", err)
		return
	}

	key := binary.LittleEndian.Uint64(serverPlaintextData)
	clientNum := dh64.Secret(privateKey, key)
	var clientNonce [8]byte
	binary.LittleEndian.PutUint64(clientNonce[:], clientNum)
	clientCodec.SetWriteNonce(clientNonce[:])
	clientCodec.SetWriteNonce(clientNonce[:])

	data := []byte("sdnajfhnoui324-hjfo[eqwihui324")
	testData := make([]byte, len(data)+int(macLen))
	copy(testData[macLen:], data)

	cipherData, err := clientCodec.Encrypto(testData)
	if err != nil {
		t.Fatalf("clientCodec.Encrypto err: %v", err)
		return
	}

	orgData, err := serverCodec.Decrypto(cipherData)
	if err != nil {
		t.Fatalf("serverCodec.Decrypto err: %v", err)
		return
	}

	t.Logf("plaintextData: %v", string(orgData))
}
