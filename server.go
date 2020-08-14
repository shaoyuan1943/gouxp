package gouxp

import (
	"encoding/binary"
	"net"
	"sync/atomic"

	"github.com/shaoyuan1943/gouxp/dh64"

	"github.com/shaoyuan1943/gokcp"
)

type Server struct {
	// connection
	rwc net.PacketConn

	// callback for some events in server
	handler ServerHandler

	// all clients, if client lost or disconnected, Server will delete *Conn
	conns map[string]*ServerConn

	connGoneC chan *ServerConn

	// user shuts down manually
	closeC chan struct{}

	closed atomic.Value

	scheduler *TimerScheduler

	cryptoCodec CryptoCodec
}

func (s *Server) notifyConnHasGone(conn *ServerConn) {
	s.connGoneC <- conn
}

func (s *Server) checkConns() {
	for {
		select {
		case conn := <-s.connGoneC:
			if _, ok := s.conns[conn.addr.String()]; ok {
				delete(s.conns, conn.addr.String())
			}
		case <-s.closeC:
			return
		}
	}
}

func (s *Server) readRawDataLoop() {
	buffer := make([]byte, gokcp.KCP_MTU_DEF)
	for {
		select {
		case <-s.closeC:
			return
		default:
			n, addr, err := s.rwc.ReadFrom(buffer)
			if err != nil {
				s.close(err)
				return
			}

			if n > 0 {
				s.onRecvRawData(addr, buffer[:n])
			}
		}
	}
}

func (s *Server) onHeartbeat(conn *ServerConn, data []byte) {}

func (s *Server) onNewConnection(addr net.Addr, data []byte) {
	conn := &ServerConn{}
	s.handler.OnNewClientComing(conn)

	if conn.cryptoCodec != nil {
		plainData, err := conn.cryptoCodec.Decrypto(data)
		if err != nil {
			return
		}

		data = plainData
	}

	protoType := ProtoType(binary.LittleEndian.Uint16(data))
	if protoType != protoTypeHandshake {
		return
	}

	data = data[protoSize:]
	convID := binary.LittleEndian.Uint32(data)
	if convID == 0 {
		return
	}

	clientPublicKey := binary.LittleEndian.Uint64(data[2:])
	if clientPublicKey == 0 {
		return
	}

	serverPrivateKey, serverPublicKey := dh64.KeyPair()
	num := dh64.Secret(serverPrivateKey, clientPublicKey)
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], num)

	var handshakeRspBuffer [PacketHeaderSize + 8]byte
	binary.LittleEndian.PutUint16(handshakeRspBuffer[macSize:], uint16(protoTypeHandshake))
	binary.LittleEndian.PutUint64(handshakeRspBuffer[PacketHeaderSize:], serverPublicKey)
	cipherData, err := conn.cryptoCodec.Encrypto(handshakeRspBuffer[:])
	if err != nil {
		return
	}

	_, err = s.rwc.WriteTo(cipherData, addr)
	if err != nil {
		return
	}

	conn.cryptoCodec.SetReadNonce(nonce[:])
	conn.cryptoCodec.SetWriteNonce(nonce[:])

	conn.convID = convID
	conn.rwc = s.rwc
	conn.addr = addr
	conn.kcp = gokcp.NewKCP(convID, conn.onKCPDataOutput)
	conn.kcp.SetBufferReserved(int(PacketHeaderSize))
	conn.kcp.SetNoDelay(true, 10, 2, true)

	s.conns[addr.String()] = conn
}

func (s *Server) onRecvRawData(addr net.Addr, data []byte) {
	conn, ok := s.conns[addr.String()]
	if !ok {
		s.onNewConnection(addr, data)
		return
	}

	if conn.cryptoCodec != nil {
		plainData, err := conn.cryptoCodec.Decrypto(data)
		if err != nil {
			conn.close(err)
			return
		}

		data = plainData
	}

	protoType := ProtoType(binary.LittleEndian.Uint16(data))
	data = data[protoSize:]
	if protoType == protoTypeHandshake {
		s.onNewConnection(addr, data)
	} else if protoType == protoTypeHeartbeat {
		s.onHeartbeat(conn, data)
	} else if protoType == protoTypeData {
		err := conn.onKCPDataComing(data)
		if err != nil {
			conn.close(err)
			return
		}
	} else {
		// TODO: unknown protocol type
	}
}

// user shuts down manually
func (s *Server) Close() {
	s.close(nil)
}

func (s *Server) close(err error) {
	if s.closed.Load().(bool) == true {
		return
	}

	close(s.closeC)
	// TODO: need locker
	for _, conn := range s.conns {
		conn.close(err)
	}

	s.closed.Store(true)
	s.handler.OnClosed(err)
}

func (s *Server) SetCryptoCodec(cryptoCodec CryptoCodec) {
	if cryptoCodec != nil {
		s.cryptoCodec = cryptoCodec
	}
}

func NewServer(rwc net.PacketConn, handler ServerHandler, parallelCount uint32) *Server {
	if rwc == nil || handler == nil {
		panic("Invalid params.")
	}

	s := &Server{
		rwc:       rwc,
		handler:   handler,
		conns:     make(map[string]*ServerConn),
		connGoneC: make(chan *ServerConn, 32),
		closeC:    make(chan struct{}),
		scheduler: NewTimerScheduler(parallelCount),
	}
	s.closed.Store(true)
	s.SetCryptoCodec(CreateCryptoCodec(UseChacha20))
	go s.checkConns()
	return s
}
