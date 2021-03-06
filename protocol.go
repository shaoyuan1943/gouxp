package gouxp

import (
	"encoding/binary"
)

// gouxp packet format:
// |--MAC--|--PROTO TYPE--|-----------------USER DATA-----------------|
// | 16byte|     2byte    |                 ...                       |
//                        |-------KCP HEADER-------|-------DATA-------|

// MAC: check data integrity

// packet protocol:
// raw data -> kcp data -> [compress] -> [crypto] -> fec
const (
	macSize          uint16 = 16
	protoSize        uint16 = 2
	PacketHeaderSize uint16 = macSize + protoSize
)

type ProtoType uint16

const (
	protoTypeHandshake ProtoType = 0x0C
	protoTypeHeartbeat ProtoType = 0x0D
	protoTypeData      ProtoType = 0x0E
)

type PlaintextData []byte

func (p PlaintextData) Type() ProtoType {
	return ProtoType(binary.LittleEndian.Uint16(p))
}

func (p PlaintextData) Data() []byte {
	return p[protoSize:]
}

var ConvID uint32 = 555

const (
	// | header: 18bytes | convID: 4bytes | crypto public key: 8bytes |
	handshakeBufferSize = PacketHeaderSize + 4 + 8
	heartbeatBufferSize = PacketHeaderSize + 4
)

var logger Logger

func SetDebugLogger(l Logger) {
	logger = l
}
