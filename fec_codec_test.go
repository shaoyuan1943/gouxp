package gouxp

import (
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	"github.com/shaoyuan1943/gokcp"
)

func getRandIndex(maxValue int) (rand1, rand2, rand3, rand4 int) {
	mp := make(map[int]int)
	for {
		if len(mp) >= 4 {
			break
		}

		randValue := rand.Intn(maxValue)
		if _, ok := mp[randValue]; ok {
			continue
		} else {
			mp[randValue] = randValue
		}
	}

	v := make([]int, 4)
	v = v[:0]
	for k, _ := range mp {
		v = append(v, k)
	}

	rand1 = v[0]
	rand2 = v[1]
	rand3 = v[2]
	rand4 = v[3]
	return
}

func TestFecCodec(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	testdata := make([][]byte, 13)
	testdata[0] = []byte("fsfdsf43578239fsd")
	testdata[1] = []byte("43534590234fasdbfnvjkashf")
	testdata[2] = []byte("fwqefsdakfhjna;wiksdf9032475902347")
	testdata[3] = []byte("fasdglfkper[]tope-gfl[wpevkle")
	testdata[4] = []byte("afdoiru43098hfjasd'optieoprifsadfr3efvedvte")
	testdata[5] = []byte("5478432967489fnsadfjkasdkfwfdsfasdf234tr3453534534fde")
	testdata[6] = []byte("wfmn;oi3kuhr48932yfhsadjhfvckjdsahfjdsf[3fasdfas'f;sad'f")
	testdata[7] = []byte("f43n8ofy43p8fh3p8haisdhf80941ho;iasjhnifoahwe")
	testdata[8] = []byte("fnpo34hp84h34f8hweafhcnaskljcfidsjdcf0j4-89jh4h3noihjkhj5ipo234u859-23y49p8r34")
	testdata[9] = []byte("sdnajfhnoui324-hjfo[eqwihui324hf835498248fbjwadefbrwqekf-30ef=-[]f[]sdfsdfbu43i74fgs[w0re")
	testdata[10] = []byte("fshfewiufh")
	testdata[11] = []byte("42389379fsdhaiofhasdkjfhiuo3hoi34hfli34")
	testdata[12] = []byte("fsd34809f43-2fhsdioafhio324h8r1h43fh4389hf9843hf8hsadiofhafh842391h348")

	encoder := NewFecEncoder(4, 2, 0)
	decoder := NewFecDecoder(4, 2, 0)

	for i := 0; i < 100000; i++ {
		rawDatas := make([][]byte, 4)
		adjust := make([][]byte, 4)
		rand1, rand2, rand3, rand4 := getRandIndex(12)
		data1 := testdata[rand1]
		data2 := testdata[rand2]
		data3 := testdata[rand3]
		data4 := testdata[rand4]
		adjust[0] = data1
		adjust[1] = data2
		adjust[2] = data3
		adjust[3] = data4

		rawDatas[0] = make([]byte, len(data1)+10)
		copy(rawDatas[0][10:], data1)
		binary.LittleEndian.PutUint32(rawDatas[0][6:], uint32(len(data1)))
		_, err := encoder.Encode(rawDatas[0])
		if err != nil {
			t.Fatalf("encode err1: %v", err)
			return
		}

		rawDatas[1] = make([]byte, len(data2)+10)
		copy(rawDatas[1][10:], data2)
		binary.LittleEndian.PutUint32(rawDatas[1][6:], uint32(len(data2)))
		_, err = encoder.Encode(rawDatas[1])
		if err != nil {
			t.Fatalf("encode err2: %v", err)
			return
		}

		rawDatas[2] = make([]byte, len(data3)+10)
		copy(rawDatas[2][10:], data3)
		binary.LittleEndian.PutUint32(rawDatas[2][6:], uint32(len(data3)))
		_, err = encoder.Encode(rawDatas[2])
		if err != nil {
			t.Fatalf("encode err3: %v", err)
			return
		}

		rawDatas[3] = make([]byte, len(data4)+10)
		copy(rawDatas[3][10:], data4)
		binary.LittleEndian.PutUint32(rawDatas[3][6:], uint32(len(data4)))
		fecData, err := encoder.Encode(rawDatas[3])
		if err != nil {
			t.Fatalf("encode err4: %v", err)
			return
		}

		if len(fecData) <= 0 {
			t.Fatalf("fec data len is 0")
			return
		}

		rand1, rand2, rand3, rand4 = getRandIndex(6)
		_, err = decoder.Decode(fecData[rand4], gokcp.SetupFromNowMS())
		if err != nil {
			t.Fatalf("decode err1: %v", err)
			return
		}

		_, err = decoder.Decode(fecData[rand1], gokcp.SetupFromNowMS())
		if err != nil {
			t.Fatalf("decode err2: %v", err)
			return
		}

		_, err = decoder.Decode(fecData[rand3], gokcp.SetupFromNowMS())
		if err != nil {
			t.Fatalf("decode err3: %v", err)
			return
		}

		codecData, err := decoder.Decode(fecData[rand2], gokcp.SetupFromNowMS())
		if err != nil {
			t.Fatalf("decode err4: %v", err)
			return
		}

		if len(codecData) <= 0 {
			t.Fatalf("codec data len is 0")
			return
		}

		for k := 0; k < len(codecData); k++ {
			l := binary.LittleEndian.Uint32(codecData[k])
			if l <= 0 {
				t.Fatalf("data len is 0")
				return
			}

			if string(codecData[k][4:4+l]) != string(adjust[k]) {
				return
			}
		}
	}
}
