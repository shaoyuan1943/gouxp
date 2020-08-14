package gouxp

import (
	"net"

	"github.com/shaoyuan1943/gokcp"
)

type ServerConn struct {
	convID uint32
	RawConn
}

func NewServerConn(convID uint32, rwc net.PacketConn, addr net.Addr, handler ConnHandler) *ServerConn {
	conn := &ServerConn{}
	conn.rwc = rwc
	conn.addr = addr
	conn.handler = handler
	conn.kcp = gokcp.NewKCP(convID, conn.onKCPDataOutput)
	return conn
}
