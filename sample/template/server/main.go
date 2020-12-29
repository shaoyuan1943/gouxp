package main

import (
	"net"

	"github.com/shaoyuan1943/gouxp"
)

type Session struct {
	*gouxp.ServerConn
}

func (u *Session) OnClosed(err error)          {}
func (u *Session) OnNewDataComing(data []byte) {}
func (u *Session) OnReady()                    {}

type Server struct {
	*gouxp.Server
}

func (s *Server) OnNewConnComing(conn *gouxp.ServerConn) {
	session := &Session{}
	session.ServerConn = conn
	session.SetConnHandler(session)
	// session.SetMTU
	// session.SetUpdateInterval
	// session.SetWindow
	// session.UseCryptoCodec
	// session.EnableFEC
}

func (s *Server) OnConnClosed(conn *gouxp.ServerConn, err error) {}
func (s *Server) OnClosed(err error)                             {}

func main() {
	addr := "127.0.0.1:9000"
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return
	}

	server := &Server{}
	server.Server = gouxp.NewServer(conn, server, 2, 16836) // bufferLen: 16K

	// server.UseCryptoCodec
	server.Start()

	// server.Close
	return
}
