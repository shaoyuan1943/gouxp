package gouxp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/shaoyuan1943/gokcp"

	"github.com/klauspost/reedsolomon"
)

const (
	FECDataShards   = 3
	FECParityShards = 2
	fecCmdData      = 0x0F
	fecCmdParity    = 0x0E
	fecResultSize   = 50
	fecDataTimeout  = 10000
	fecHeaderOffset = 6
	fecLengthOffset = 2
	fecHeaderSize   = fecHeaderOffset + fecLengthOffset
)

var (
	ErrUnknownFecCmd  = errors.New("unknown fec cmd")
	ErrFecDataTimeout = errors.New("fec data timeout")
	ErrNoFecData      = errors.New("no fec data")
)

var fecBufferPool sync.Pool

func bufferFromPool(size int) []byte {
	if fecBufferPool.New == nil {
		fecBufferPool.New = func() interface{} {
			buffer := make([]byte, size)
			return buffer
		}
	}

	buffer := fecBufferPool.Get().([]byte)
	buffer = buffer[:0]
	return buffer
}

func bufferBackPool(buffer []byte) {
	if buffer != nil {
		fecBufferPool.Put(buffer)
	}
}

func isFECFormat(data []byte) bool {
	if data == nil || len(data) <= 0 {
		return false
	}

	fecCmd := binary.LittleEndian.Uint16(data[4:])
	if int(fecCmd) != fecCmdData && int(fecCmd) != fecCmdParity {
		return false
	}

	return true
}

type FecCodecEncoder struct {
	codec          reedsolomon.Encoder
	q              [][]byte
	insertIndex    int
	nextSN         int32
	shards         int
	dataShards     int
	parityShards   int
	maxRawDataLen  int
	zero           []byte
	codecData      [][]byte
	offset         int
	bufferSize     int
	lastInsertTime uint32
}

func NewFecEncoder(dataShards, parityShards, bufferSize int) *FecCodecEncoder {
	fecEncoder := &FecCodecEncoder{}
	fecEncoder.shards = dataShards + parityShards
	fecEncoder.dataShards = dataShards
	fecEncoder.parityShards = parityShards
	encoder, err := reedsolomon.New(fecEncoder.dataShards, fecEncoder.parityShards)
	if err != nil {
		panic(fmt.Sprintf("init fec encoder: %v", err))
	}

	fecEncoder.codec = encoder
	fecEncoder.codecData = make([][]byte, fecEncoder.shards)
	fecEncoder.bufferSize = bufferSize
	fecEncoder.zero = make([]byte, bufferSize)
	fecEncoder.q = make([][]byte, fecEncoder.shards)
	for i := 0; i < fecEncoder.shards; i++ {
		fecEncoder.q[i] = make([]byte, bufferSize)
		fecEncoder.q[i] = fecEncoder.q[i][:0]
	}

	return fecEncoder
}

func (f *FecCodecEncoder) Encode(rawData []byte) (fecData [][]byte, err error) {
	if rawData == nil || len(rawData) == 0 || len(rawData) > f.bufferSize {
		panic("raw data length invalid")
	}

	n := len(rawData)
	f.q[f.insertIndex] = f.q[f.insertIndex][:fecHeaderSize+n]
	copy(f.q[f.insertIndex][fecHeaderSize:], rawData)
	binary.LittleEndian.PutUint16(f.q[f.insertIndex][fecHeaderOffset:], uint16(n))
	f.lastInsertTime = gokcp.SetupFromNowMS()

	if n > f.maxRawDataLen {
		f.maxRawDataLen = n
	}

	if (f.insertIndex + 1) == f.dataShards {
		maxLen := f.maxRawDataLen + fecHeaderSize
		for i := 0; i < (f.dataShards + f.parityShards); i++ {
			if i >= f.dataShards {
				f.q[i] = f.q[i][:maxLen]
				f.codecData[i] = f.q[i][fecHeaderOffset:maxLen]
			} else {
				orgLen := len(f.q[i])
				if orgLen < maxLen {
					f.q[i] = f.q[i][:maxLen]
					copy(f.q[i][orgLen:maxLen], f.zero)
				}

				f.codecData[i] = f.q[i][fecHeaderOffset:maxLen]
			}
		}

		err = f.codec.Encode(f.codecData)
		if err != nil {
			return
		}

		for i := 0; i < (f.dataShards + f.parityShards); i++ {
			if i >= f.dataShards {
				f.markParity(f.q[i])
			} else {
				f.markData(f.q[i])
			}
		}

		f.insertIndex = 0
		f.maxRawDataLen = 0

		fecData = f.q
		err = nil
		return
	}

	f.insertIndex++
	return
}

func (f *FecCodecEncoder) markData(data []byte) {
	binary.LittleEndian.PutUint32(data[:4], uint32(f.nextSN))
	binary.LittleEndian.PutUint16(data[4:fecHeaderOffset], uint16(fecCmdData))
	f.nextSN++
}

func (f *FecCodecEncoder) markParity(data []byte) {
	binary.LittleEndian.PutUint32(data[:4], uint32(f.nextSN))
	binary.LittleEndian.PutUint16(data[4:fecHeaderOffset], uint16(fecCmdParity))
	f.nextSN++
}

type DataShards struct {
	q             [][]byte
	o             [][]byte
	lastInsert    uint32
	insertIndex   int
	decoded       bool
	maxRawDataLen int
	shardsCount   int
}

type FecCodecDecoder struct {
	codec        reedsolomon.Encoder
	shards       int
	dataShards   int
	parityShards int
	rawDatas     map[int]DataShards
	result       [][]byte
	offset       int
	bufferSize   int
}

func NewFecDecoder(dataShards, parityShards, bufferSize int) *FecCodecDecoder {
	fecDecoder := &FecCodecDecoder{}
	fecDecoder.shards = dataShards + parityShards
	fecDecoder.dataShards = dataShards
	fecDecoder.parityShards = parityShards
	decoder, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		panic(fmt.Sprintf("init fec decoder err: %v", err))
	}

	fecDecoder.codec = decoder
	fecDecoder.rawDatas = make(map[int]DataShards)
	fecDecoder.result = make([][]byte, fecResultSize)
	fecDecoder.bufferSize = bufferSize
	return fecDecoder
}

func (f *FecCodecDecoder) Decode(fecData []byte, now uint32) (rawData [][]byte, err error) {
	if fecData == nil || len(fecData) == 0 || len(fecData) > f.bufferSize {
		panic("raw data length invalid")
	}

	if !isFECFormat(fecData) {
		return nil, ErrUnknownFecCmd
	}

	sn := binary.LittleEndian.Uint32(fecData)
	startRange := int(sn) - (int(sn) % f.shards)
	endRange := startRange + f.shards + 1
	sumIndex := 0
	for i := startRange; i < endRange; i++ {
		sumIndex += i
	}

	ds, ok := f.rawDatas[sumIndex]
	if !ok {
		ds = DataShards{}
		ds.o = make([][]byte, f.shards)
		ds.q = make([][]byte, f.shards)
		for i := 0; i < len(ds.q); i++ {
			ds.o[i] = bufferFromPool(f.bufferSize)
			ds.q[i] = ds.o[i]
		}
	}

	ds.q[int(sn)-startRange] = ds.q[int(sn)-startRange][:len(fecData)]
	copy(ds.q[int(sn)-startRange], fecData)
	ds.shardsCount++

	if len(fecData) > ds.maxRawDataLen {
		ds.maxRawDataLen = len(fecData)
	}

	ds.lastInsert = now
	f.rawDatas[sumIndex] = ds

	f.result = f.result[:0]
	for k, v := range f.rawDatas {
		if v.decoded {
			f.delShards(k)
			continue
		}

		if len(f.result) >= fecResultSize || (len(f.result)+f.dataShards) >= fecResultSize {
			break
		}

		if v.shardsCount >= f.dataShards {
			codec := v.q
			for i := 0; i < len(v.q); i++ {
				d := v.q[i]
				if len(d) > 0 {
					sn = binary.LittleEndian.Uint32(d)
					startRange = int(sn) - (int(sn) % f.shards)
					codec[(int(sn) - startRange)] = d[fecHeaderOffset:]
				}
			}

			err = f.codec.ReconstructData(codec)
			if err != nil {
				return
			}

			reconstructed := codec[:f.dataShards]
			for i := 0; i < len(reconstructed); i++ {
				n := binary.LittleEndian.Uint16(reconstructed[i])
				if n > 0 {
					reconstructed[i] = reconstructed[i][fecLengthOffset:]
					reconstructed[i] = reconstructed[i][:n]
				}
			}

			v.decoded = true
			f.result = append(f.result, reconstructed...)
			f.rawDatas[k] = v
			continue
		}

		// timeout
		if (now-v.lastInsert) > fecDataTimeout && !v.decoded {
			f.delShards(k)
		}
	}

	rawData = f.result
	err = nil
	return
}

func (f *FecCodecDecoder) delShards(sumIndex int) {
	ds, ok := f.rawDatas[sumIndex]
	if !ok {
		return
	}

	for i := 0; i < f.shards; i++ {
		if ds.o[i] != nil {
			bufferBackPool(ds.o[i])
		}
	}

	ds.q = nil
	ds.o = nil

	delete(f.rawDatas, sumIndex)
}
