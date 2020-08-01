package gouxp

import (
	"github.com/shaoyuan1943/gokcp"
)

// gouxp message format:
// |---SUM---|---CMD---|---LENGTH---|---EXTRA---|---CRYPTO---|---COMPRESS---|---USER DATA---|
// |  4byte  |  2byte  |   2byte    |    2byte  |    1byte   |     1byte    |     ...       |
//															                |    KCP DATA   |
// SUM: check data integrity
// CMD: data type, value type is CmdID
// LENGTH: length of user data
// EXTRA: special information to clients
// CRYPTO: crypto flag
// COMPRESS: compress flag

// message protocol:
// raw data -> kcp data -> compress -> crypto -> fec
const (
	sumLen           uint32 = 4
	cmdLen           uint32 = 2
	dataLen          uint32 = 2
	extraLen         uint32 = 2
	cryptoLen        uint32 = 1
	compressLen      uint32 = 1
	kcpHeader        uint32 = gokcp.KCP_OVERHEAD
	MessageHeaderLen uint32 = sumLen + cmdLen + dataLen + extraLen + cryptoLen + compressLen + kcpHeader
)

type CmdID uint16

const (
	cmdHello      CmdID = 0x01
	cmdDataComing CmdID = 0x02
	cmdGoodbye    CmdID = 0x03
)

type SessionState uint16

const (
	stateUnknow SessionState = 0x04
	stateReady  SessionState = 0x05
	stateGone   SessionState = 0x06
)

var ConvID uint32 = 555
