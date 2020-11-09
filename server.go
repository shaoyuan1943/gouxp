package gouxp

import (
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shaoyuan1943/gouxp/dh64"

	"github.com/shaoyuan1943/gokcp"
)

type Server struct {
	rwc            net.PacketConn
	handler        ServerHandler
	allConn        map[string]*ServerConn
	closeC         chan struct{}
	scheduler      *TimerScheduler
	started        int64
	connCryptoType CryptoType
	sync.Mutex
}

func (s *Server) UseCryptoCodec(cryptoType CryptoType) {
	s.Lock()
	defer s.Unlock()

	s.connCryptoType = cryptoType
}

func (s *Server) waiting4Start() {
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

func (s *Server) findConnection(addr net.Addr) *ServerConn {
	s.Lock()
	defer s.Unlock()

	return s.allConn[addr.String()]
}

func (s *Server) addConnection(addr net.Addr, conn *ServerConn) {
	s.Lock()
	defer s.Unlock()

	s.allConn[addr.String()] = conn
}

func (s *Server) removeConnection(conn *ServerConn) {
	s.Lock()
	defer s.Unlock()

	if _, ok := s.allConn[conn.addr.String()]; ok {
		delete(s.allConn, conn.addr.String())
	}
}

func (s *Server) readRawDataLoop() {
	defer func() {
		if r := recover(); r != nil {
			var stackBuffer [4096]byte
			n := runtime.Stack(stackBuffer[:], false)
			if logger != nil {
				logger.Errorf("server exit from panic: %v", stackBuffer[:n])
			}

			s.close(errors.New("server exit from panic"))
		}
	}()

	s.waiting4Start()
	buffer := make([]byte, maxDataLengthLimit)
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
	plaintextData, err := conn.decrypt(data)
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

	cipherData, err := conn.encrypt(handshakeRspBuffer[:])
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
	conn.connCloser = conn
	conn.closeC = make(chan struct{})
	conn.server = s
	conn.onHandshaked()
	s.handler.OnNewConnComing(conn)
	conn.kcpDataBuffer = make([]byte, maxDataLengthLimit)
	return conn, nil
}

func (s *Server) onRecvRawData(addr net.Addr, data []byte) {
	conn := s.findConnection(addr)
	if conn == nil {
		newConn, err := s.onNewConnection(addr, data)
		if err != nil {
			return
		}

		s.addConnection(addr, newConn)
		return
	}

	atomic.StoreUint32(&conn.lastActiveTime, gokcp.SetupFromNowMS())

	var err error
	defer func() {
		if err != nil {
			conn.close(err)
		}
	}()

	parseData := func(targetData []byte) error {
		plaintextData, parseErr := conn.decrypt(targetData)
		if parseErr != nil {
			return parseErr
		}

		protoType := PlaintextData(plaintextData).Type()
		logicData := PlaintextData(plaintextData).Data()
		switch protoType {
		case protoTypeHandshake:
			parseErr = ErrExistConnection
		case protoTypeHeartbeat:
			parseErr = conn.onHeartbeat(logicData)
		case protoTypeData:
			parseErr = conn.onKCPDataInput(logicData)
		default:
			parseErr = ErrUnknownProtocolType
		}

		return parseErr
	}

	if conn.fecEncoder != nil && conn.fecDecoder != nil {
		var rawData [][]byte
		rawData, err = conn.fecDecoder.Decode(data, gokcp.SetupFromNowMS())
		if err != nil {
			if err == ErrUnknownFecCmd {
				err = parseData(data)
				if err != nil {
					return
				}
			}

			return
		}

		if len(rawData) > 0 {
			for _, v := range rawData {
				if len(v) > 0 {
					err = parseData(v)
					if err != nil {
						return
					}
				}
			}
		}
	} else {
		err = parseData(data)
		if err != nil {
			return
		}
	}

	return
}

// user shuts down manually
func (s *Server) Close() {
	s.close(nil)
}

func (s *Server) close(err error) {
	s.scheduler.Close()

	s.Lock()
	tmp := make([]*ServerConn, len(s.allConn))
	tmp = tmp[:0]
	for _, conn := range s.allConn {
		tmp = append(tmp, conn)
	}
	s.Unlock()

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
	s := &Server{
		rwc:       rwc,
		handler:   handler,
		allConn:   make(map[string]*ServerConn),
		closeC:    make(chan struct{}),
		scheduler: NewTimerScheduler(parallelCount),
	}

	go s.readRawDataLoop()
	return s
}
