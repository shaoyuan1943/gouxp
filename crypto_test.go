package gouxp

import (
	"testing"
)

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
	codec := CreateCryptoCodec(UseSalsa20)
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

	chacha20Codec := CreateCryptoCodec(UseChacha20)
	testErrorCrypto(t, chacha20Codec)
}
