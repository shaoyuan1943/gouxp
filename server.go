package gouxp

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shaoyuan1943/gouxp/dh64"

	"github.com/shaoyuan1943/gokcp"
)

type Server struct {
	rwc            net.PacketConn
	handler        ServerHandler
	conns          map[string]*ServerConn
	closeC         chan struct{}
	closed         atomic.Value
	scheduler      *TimerScheduler
	locker         sync.Mutex
	started        int64
	connCryptoType CryptoType
}

func (s *Server) UseCryptoCodec(cryptoType CryptoType) {
	s.locker.Lock()
	defer s.locker.Unlock()

	s.connCryptoType = cryptoType
}

func (s *Server) waitForStart() {
	for {
		if atomic.LoadInt64(&s.started) != 0 {
			return
		}
		select {
		case <-s.closeC:
			return
		default:
		}

		time.Sleep(1 * time.Millisecond)
	}
}

func (s *Server) getConnection(addr net.Addr) *ServerConn {
	s.locker.Lock()
	defer s.locker.Unlock()

	return s.conns[addr.String()]
}

func (s *Server) addConnection(addr net.Addr, conn *ServerConn) {
	s.locker.Lock()
	defer s.locker.Unlock()

	s.conns[addr.String()] = conn
}

func (s *Server) removeConnection(conn *ServerConn) {
	s.locker.Lock()
	defer s.locker.Unlock()

	if _, ok := s.conns[conn.addr.String()]; ok {
		delete(s.conns, conn.addr.String())
	}
}

func (s *Server) readRawDataLoop() {
	s.waitForStart()

	buffer := make([]byte, MaxMTULimit)
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

func (s *Server) onNewConnection(addr net.Addr, data []byte) (*ServerConn, error) {
	conn := &ServerConn{}
	conn.cryptoCodec = createCryptoCodec(s.connCryptoType)
	plaintextData, err := conn.decrypto(data)
	if err != nil {
		return nil, err
	}

	protoType := PlaintextData(plaintextData).Type()
	if protoType != protoTypeHandshake {
		return nil, ErrUnknownProtocolType
	}

	logicData := PlaintextData(plaintextData).Data()
	convID := binary.LittleEndian.Uint32(logicData)
	if convID == 0 {
		return nil, gokcp.ErrDataInvalid
	}

	var nonce [8]byte
	var handshakeRspBuffer [PacketHeaderSize + 8]byte
	binary.LittleEndian.PutUint16(handshakeRspBuffer[macSize:], uint16(protoTypeHandshake))
	if conn.cryptoCodec != nil {
		clientPublicKey := binary.LittleEndian.Uint64(logicData[4:])
		if clientPublicKey == 0 {
			return nil, gokcp.ErrDataInvalid
		}

		serverPrivateKey, serverPublicKey := dh64.KeyPair()
		num := dh64.Secret(serverPrivateKey, clientPublicKey)
		binary.LittleEndian.PutUint64(nonce[:], num)
		binary.LittleEndian.PutUint64(handshakeRspBuffer[PacketHeaderSize:], serverPublicKey)
	}

	cipherData, err := conn.encrypto(handshakeRspBuffer[:])
	if err != nil {
		return nil, err
	}

	_, err = s.rwc.WriteTo(cipherData, addr)
	if err != nil {
		return nil, err
	}

	if conn.cryptoCodec != nil {
		conn.cryptoCodec.SetReadNonce(nonce[:])
		conn.cryptoCodec.SetWriteNonce(nonce[:])
	}

	conn.convID = convID
	conn.rwc = s.rwc
	conn.addr = addr
	conn.kcp = gokcp.NewKCP(convID, conn.onKCPDataOutput)
	conn.kcp.SetBufferReserved(int(PacketHeaderSize))
	conn.kcp.SetNoDelay(true, 10, 2, true)
	conn.closed.Store(false)
	conn.closer = conn
	conn.closeC = make(chan struct{})
	conn.server = s
	conn.onHandshaked()
	s.handler.OnNewClientComing(conn)

	return conn, nil
}

func (s *Server) onRecvRawData(addr net.Addr, data []byte) {
	conn := s.getConnection(addr)
	if conn == nil {
		newConn, err := s.onNewConnection(addr, data)
		if err != nil {
			return
		}

		s.addConnection(addr, newConn)
		return
	}

	atomic.StoreUint32(&conn.lastActiveTime, gokcp.SetupFromNowMS())

	var plaintextData []byte
	var err error
	defer func() {
		if err != nil {
			conn.close(err)
		}
	}()

	plaintextData, err = conn.decrypto(data)
	if err != nil {
		return
	}

	protoType := PlaintextData(plaintextData).Type()
	logicData := PlaintextData(plaintextData).Data()
	switch protoType {
	case protoTypeHandshake:
		// TODO: if connection is exist but client send handshake protocol, WHY?
		panic("exist connection recv handshake protocol")
	case protoTypeHeartbeat:
		err = conn.onHeartbeat(logicData)
	case protoTypeData:
		err = conn.onKCPDataInput(logicData)
	default:
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

	s.closed.Store(true)

	s.locker.Lock()
	tmp := make([]*ServerConn, len(s.conns))
	for _, conn := range s.conns {
		tmp = append(tmp, conn)
	}
	s.locker.Unlock()

	for _, conn := range tmp {
		conn.close(err)
	}

	close(s.closeC)
	s.handler.OnClosed(err)
}

func (s *Server) Start() {
	if atomic.LoadInt64(&s.started) == 0 {
		atomic.StoreInt64(&s.started, 1)
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
		closeC:    make(chan struct{}),
		scheduler: NewTimerScheduler(parallelCount),
	}

	s.closed.Store(false)
	go s.readRawDataLoop()
	return s
}
