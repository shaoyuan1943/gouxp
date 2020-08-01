package gouxp

import "net"

type Server struct {
	// connection
	rwc net.PacketConn

	// callback for some events in server
	handler ServerHandler

	// all clients, if client lost or disconnected, Server will delete *Conn
	conns map[string]*Conn

	connGoneC chan *Conn

	// user shuts down manually
	exitC chan struct{}
}

func (s *Server) notifyConnHasGone(conn *Conn) {
	s.connGoneC <- conn
}

func (s *Server) checkConns() {
	for {
		select {
		case conn := <-s.connGoneC:
			if _, ok := s.conns[conn.addr.String()]; ok {
				delete(s.conns, conn.addr.String())
			}
		case <-s.exitC:
			return
		}
	}
}

func (s *Server) readLoop() {
	for {
		select {
		case <-s.exitC:
			return
		default:
		}

	}
}

// user shuts down manually
func (s *Server) Close() {

}

func NewServer(rwc net.PacketConn, handler ServerHandler) *Server {
	if rwc == nil || handler == nil {
		panic("Invalid params.")
	}

	s := &Server{
		rwc:       rwc,
		handler:   handler,
		conns:     make(map[string]*Conn),
		connGoneC: make(chan *Conn, 32),
		exitC:     make(chan struct{}),
	}

	go s.checkConns()
	return s
}
