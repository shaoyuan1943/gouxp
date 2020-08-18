package gouxp

import (
	"time"

	"github.com/shaoyuan1943/gokcp"
)

// gouxp packet format:
// |---MAC---|---PROTO TYPE---|-----------------USER DATA-----------------|
// |  16byte |     2byte      |                 ...                       |
//                            |-------KCP HEADER-------|-------DATA-------|

// MAC: check data integrity

// packet protocol:
// raw data -> kcp data -> compress -> crypto -> fec
const (
	macSize          uint16 = 16
	protoSize        uint16 = 2
	PacketHeaderSize uint16 = macSize + protoSize
)

type ProtoType uint16

const (
	protoTypeHandshake ProtoType = 0x01
	protoTypeHeartbeat ProtoType = 0x02
	protoTypeData      ProtoType = 0x03
)

var ConvID uint32 = 555

func NowMS() int64 {
	return time.Now().Unix()
}

const (
	// | header: 18bytes | convID: 4bytes | crypto public key: 8bytes |
	handshakeBufferSize = PacketHeaderSize + 4 + 8
	MaxBufferSize       = gokcp.KCP_MTU_DEF * 3
)
