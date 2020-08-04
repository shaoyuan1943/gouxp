package gouxp

import (
	"github.com/shaoyuan1943/gokcp"
)

// gouxp message format:
// |---MAC---|---CMD---|---EXTRA---|---USER DATA---|
// |  16byte |  2byte  |    2byte  |     ...       |
//								   |    KCP DATA   |
// MAC: check data integrity
// CMD: data type, value type is CmdID

// message protocol:
// raw data -> kcp data -> compress -> crypto -> fec
const (
	macLen           uint32 = 16
	cmdLen           uint32 = 2
	extraLen         uint32 = 2
	kcpHeader        uint32 = gokcp.KCP_OVERHEAD
	MessageHeaderLen uint32 = macLen + cmdLen + extraLen + kcpHeader
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
