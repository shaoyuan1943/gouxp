package gouxp

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/shaoyuan1943/gokcp"
)

type Conn struct {
	convID  uint32
	rwc     net.PacketConn
	addr    net.Addr
	server  *Server
	handler ConnHandler
	kcp     *gokcp.KCP
	closeC  chan struct{}
	closed  atomic.Value
	locker  sync.Mutex
}

func (conn *Conn) IsClient() bool {
	return conn.server == nil
}

// user shuts down manually
func (conn *Conn) Close() {
	conn.close(nil)
}

func (conn *Conn) close(err error) {
	if conn.closed.Load() == true {
		return
	}

	close(conn.closeC)
	if !conn.IsClient() {
		conn.server.notifyConnHasGone(conn)
	}

	conn.closed.Store(bool(true))
	conn.handler.OnClosed(err)
}

//
func (conn *Conn) handleData(data []byte) {

}

// when |conn| is client side
func (conn *Conn) readLoop() {
	if !conn.IsClient() {
		return
	}

	buffer := make([]byte, conn.kcp.Mtu())
	for {
		select {
		case <-conn.closeC:
			return
		default:
			n, addr, err := conn.rwc.ReadFrom(buffer)
			if err != nil {
				conn.close(err)
				return
			}

			if addr.String() != conn.addr.String() {
				conn.close(ErrDifferentAddr)
				return
			}

			conn.handleData(buffer[:n])
		}
	}
}

func (conn *Conn) onKCPDataOutput(data []byte) {

}

func NewConnFromServer(convID uint32, addr net.Addr, s *Server) *Conn {
	return newConn(convID, nil, addr, s, nil)
}

func newConn(convID uint32, rwc net.PacketConn, addr net.Addr, s *Server, handler ConnHandler) *Conn {
	conn := &Conn{
		convID:  convID,
		rwc:     rwc,
		addr:    addr,
		server:  s,
		handler: handler,
		closeC:  make(chan struct{}),
	}

	conn.closed.Store(bool(false))
	conn.kcp = gokcp.NewKCP(convID, conn.onKCPDataOutput)
	conn.kcp.SetBufferReserved(int(MessageHeaderLen))
	conn.kcp.SetNoDelay(true, 10, 2, true)

	return conn
}

func NewConn(conn net.PacketConn, addr net.Addr, s *Server, handler ConnHandler) *Conn {
	return newConn(atomic.AddUint32(&ConvID, 1), conn, addr, s, handler)
}
