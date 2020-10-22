package gouxp

import (
	"encoding/binary"
	"testing"

	"github.com/shaoyuan1943/gouxp/dh64"
)

var macLen = 16

func checkCrypto(t *testing.T, codec CryptCodec, data []byte) bool {
	encryptoed, err := codec.Encrypt(data)
	if err != nil {
		t.Fatalf("codec.Encrypto err: %v\n", err)
		return false
	}
	t.Logf("encryptoed: %v\n", string(encryptoed))

	plaintext, err := codec.Decrypt(encryptoed)
	if err != nil {
		t.Fatalf("codec.Decrypto err: %v\n", err)
		return false
	}

	t.Logf("%v\n", string(plaintext))
	return true
}

func testCodec(t *testing.T, codec CryptCodec) {
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

func testErrorCrypto(t *testing.T, codec CryptCodec) {
	data := []byte("f43n8ofy43p8fh3p8haisdhf80941ho;iasjhnifoahwe")
	myData := make([]byte, len(data)+int(macLen))
	copy(myData[macLen:], data)

	encryptoed, err := codec.Encrypt(myData)
	if err != nil {
		t.Fatalf("salsa20Codec.Encrypto err: %v\n", err)
		return
	}

	encryptoed[18] = 'Y'
	plaintext, err := codec.Decrypt(encryptoed)
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
	cipherData, err := codec1.Encrypt(testData)
	if err != nil {
		t.Fatalf("encrypto err: %v", err)
		return
	}
	t.Logf("cipherData: %v", cipherData)
	plaintextData, err := codec2.Decrypt(cipherData)
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
	clientCipherData, err := clientCodec.Encrypt(clientData)
	if err != nil {
		t.Fatalf("clientCodec.Encrypto err: %v", err)
		return
	}

	serverCodec := createCryptoCodec(UseSalsa20)
	plaintextData, err := serverCodec.Decrypt(clientCipherData)
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
	serverCipherData, err := serverCodec.Encrypt(serverData)
	if err != nil {
		t.Fatalf("serverCodec.Encrypto err: %v", err)
		return
	}

	serverCodec.SetReadNonce(serverNonce[:])
	serverCodec.SetWriteNonce(serverNonce[:])

	serverPlaintextData, err := clientCodec.Decrypt(serverCipherData)
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

	cipherData, err := clientCodec.Encrypt(testData)
	if err != nil {
		t.Fatalf("clientCodec.Encrypto err: %v", err)
		return
	}

	orgData, err := serverCodec.Decrypt(cipherData)
	if err != nil {
		t.Fatalf("serverCodec.Decrypto err: %v", err)
		return
	}

	t.Logf("plaintextData: %v", string(orgData))

	data = []byte("34265734g0f0473281r5671r64392-hjfo[eqwihui324")
	testData = make([]byte, len(data)+int(macLen))
	copy(testData[macLen:], data)

	cipherData, err = clientCodec.Encrypt(testData)
	if err != nil {
		t.Fatalf("clientCodec.Encrypto err: %v", err)
		return
	}

	orgData, err = serverCodec.Decrypt(cipherData)
	if err != nil {
		t.Fatalf("serverCodec.Decrypto err: %v", err)
		return
	}

	t.Logf("plaintextData: %v", string(orgData))

	codecData(t, clientCodec, serverCodec)
}

func codecData(t *testing.T, encoder, decoder CryptCodec) {
	data1 := []byte("342532452345dfsdvdfs-hjfo[eqwihui")
	testData1 := make([]byte, len(data1)+int(macLen))
	copy(testData1[macLen:], data1)

	data2 := []byte("sdnajfhn[eqwihui90-97ghivuyt")
	testData2 := make([]byte, len(data2)+int(macLen))
	copy(testData2[macLen:], data2)

	data3 := []byte("sd341348978 fcasdfhuashdfsdpfuh894390ui894")
	testData3 := make([]byte, len(data3)+int(macLen))
	copy(testData3[macLen:], data3)

	cipherData2, err := encoder.Encrypt(testData2)
	if err != nil {
		t.Fatalf("encoder.Encrypt data2 err: %v", err)
		return
	}

	cipherData1, err := encoder.Encrypt(testData1)
	if err != nil {
		t.Fatalf("encoder.Encrypt data1 err: %v", err)
		return
	}

	cipherData3, err := encoder.Encrypt(testData3)
	if err != nil {
		t.Fatalf("encoder.Encrypt data3 err: %v", err)
		return
	}

	plaintextData3, err := decoder.Decrypt(cipherData3)
	if err != nil {
		t.Fatalf("encoder.Decrypt cipherData3 err: %v", err)
		return
	}

	plaintextData1, err := decoder.Decrypt(cipherData1)
	if err != nil {
		t.Fatalf("encoder.Decrypt cipherData1 err: %v", err)
		return
	}

	plaintextData2, err := decoder.Decrypt(cipherData2)
	if err != nil {
		t.Fatalf("encoder.Decrypt cipherData2 err: %v", err)
		return
	}

	t.Logf("plaintextData1: %v", string(plaintextData1))
	t.Logf("plaintextData2: %v", string(plaintextData2))
	t.Logf("plaintextData3: %v", string(plaintextData3))
}

func TestUnorderCodec(t *testing.T) {
	encoder := createCryptoCodec(UseSalsa20)
	decoder := createCryptoCodec(UseSalsa20)

	codecData(t, encoder, decoder)
}

func exchangedCodec(t *testing.T) (CryptCodec, CryptCodec) {
	clientCodec := createCryptoCodec(UseSalsa20)
	privateKey, publicKey := dh64.KeyPair()
	clientData := make([]byte, macLen+8)
	binary.LittleEndian.PutUint64(clientData[macLen:], publicKey)
	clientCipherData, err := clientCodec.Encrypt(clientData)
	if err != nil {
		t.Fatalf("clientCodec.Encrypto err: %v", err)
		return nil, nil
	}

	serverCodec := createCryptoCodec(UseSalsa20)
	plaintextData, err := serverCodec.Decrypt(clientCipherData)
	if err != nil {
		t.Fatalf("serverCodec.Decrypto err: %v", err)
		return nil, nil
	}

	clientPublicKey := binary.LittleEndian.Uint64(plaintextData)
	serverPrivateKey, serverPublicKey := dh64.KeyPair()
	serverNum := dh64.Secret(serverPrivateKey, clientPublicKey)
	var serverNonce [8]byte
	binary.LittleEndian.PutUint64(serverNonce[:], serverNum)

	serverData := make([]byte, macLen+16)
	binary.LittleEndian.PutUint64(serverData[macLen:], serverPublicKey)
	serverCipherData, err := serverCodec.Encrypt(serverData)
	if err != nil {
		t.Fatalf("serverCodec.Encrypto err: %v", err)
		return nil, nil
	}

	serverCodec.SetReadNonce(serverNonce[:])
	serverCodec.SetWriteNonce(serverNonce[:])

	serverPlaintextData, err := clientCodec.Decrypt(serverCipherData)
	if err != nil {
		t.Fatalf("clientCodec.Decrypto err: %v", err)
		return nil, nil
	}

	key := binary.LittleEndian.Uint64(serverPlaintextData)
	clientNum := dh64.Secret(privateKey, key)
	var clientNonce [8]byte
	binary.LittleEndian.PutUint64(clientNonce[:], clientNum)
	clientCodec.SetWriteNonce(clientNonce[:])
	clientCodec.SetWriteNonce(clientNonce[:])

	return clientCodec, serverCodec
}
