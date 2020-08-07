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

const (
	heartbeatTimeout = 3
)

var zero [64]byte

type CryptoKey struct {
	publicKey  uint64
	privateKey uint64
}

type Conn struct {
	convID         uint32
	rwc            net.PacketConn
	addr           net.Addr
	server         *Server
	handler        ConnHandler
	kcp            *gokcp.KCP
	closeC         chan struct{}
	closed         atomic.Value
	locker         sync.Mutex
	cryptoCodec    CryptoCodec
	cryptoKey      CryptoKey
	started        bool
	lastActiveTime int64
	heartbeatBuff  [PacketHeaderLen + 4]byte
}

func (conn *Conn) IsClient() bool {
	return conn.server == nil
}

func (conn *Conn) SetCryptoCodec(cryptoCodec CryptoCodec) {
	if cryptoCodec != nil {
		conn.cryptoCodec = cryptoCodec
	}
}

func (conn *Conn) Start() {
	if conn.IsClient() {
		conn.sayHello()
	}
}

func (conn *Conn) heartbeat() {
	if conn.closed.Load().(bool) == true {
		return
	}

	copy(conn.heartbeatBuff[:], zero[:])
	binary.LittleEndian.PutUint16(conn.heartbeatBuff[macLen:], uint16(cmdHeartbeat))
	binary.LittleEndian.PutUint32(conn.heartbeatBuff[PacketHeaderLen:], uint32(NowMS()))
	if conn.cryptoCodec != nil {
		heartbeatData, err := conn.cryptoCodec.Encrypto(conn.heartbeatBuff[:])
		if err != nil {
			conn.close(err)
			return
		}

		copy(conn.heartbeatBuff[:], heartbeatData)
	}

	//conn.Write(conn.heartbeatBuff)
}

func (conn *Conn) onHeartbeat(data []byte) {

}

func (conn *Conn) sayHello() {
	if !conn.IsClient() {
		return
	}

	helloBuff := make([]byte, PacketHeaderLen+8)
	binary.LittleEndian.PutUint16(helloBuff[macLen:], uint16(cmdHello))
	conn.cryptoKey.privateKey, conn.cryptoKey.publicKey = dh64.KeyPair()
	binary.LittleEndian.PutUint64(helloBuff[PacketHeaderLen:], conn.cryptoKey.publicKey)
	if conn.cryptoCodec != nil {
		heartbeatData, err := conn.cryptoCodec.Encrypto(conn.heartbeatBuff[:])
		if err != nil {
			conn.close(err)
			return
		}

		copy(conn.heartbeatBuff[:], heartbeatData)
	}

	//conn.Write(helloBuff)
}

func (conn *Conn) onHello(data []byte) {
	if !conn.IsClient() {
		return
	}

	srvPublicKey := binary.LittleEndian.Uint64(data)
	num := dh64.Secret(conn.cryptoKey.privateKey, srvPublicKey)
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], num)
	conn.cryptoCodec.SetReadNonce(nonce[:])
	conn.cryptoCodec.SetWriteNonce(nonce[:])
}

// user shuts down manually
func (conn *Conn) Close() {
	conn.close(nil)
}

func (conn *Conn) close(err error) {
	if conn.closed.Load().(bool) == true {
		return
	}

	close(conn.closeC)
	if !conn.IsClient() {
		conn.server.notifyConnHasGone(conn)
	}

	conn.closed.Store(true)
	conn.handler.OnClosed(err)
}

func (conn *Conn) onDataComing(data []byte) {
	err := conn.kcp.Input(data)
	if err != nil {
		conn.close(err)
		return
	}
}

func (conn *Conn) handleRecvedData(data []byte) {
	if conn.cryptoCodec != nil {
		plaintext, err := conn.cryptoCodec.Decrypto(data)
		if err != nil {
			conn.close(err)
			return
		}

		data = plaintext
	}

	cmd := CmdID(binary.LittleEndian.Uint16(data))
	data = data[2:]
	if cmd == cmdHello {
		conn.onHello(data)
	} else if cmd == cmdHeartbeat {
		conn.onHeartbeat(data)
	} else if cmd == cmdDataComing {
		conn.onDataComing(data)
	} else {
		// err: Unknown protocol command
	}
}

func (conn *Conn) Write(data []byte) (n int, err error) {
	if len(data) <= 0 {
		return 0, gokcp.ErrDataLenInvalid
	}

	err = conn.kcp.Input(data)
	if err != nil {
		conn.close(err)
		return
	}

	n = len(data)
	err = nil
	return
}

func (conn *Conn) heartbeatLoop() {
	heartTickerC := time.NewTicker(2 * time.Second)
	defer heartTickerC.Stop()

	for {
		select {
		case <-conn.closeC:
			return
		case <-heartTickerC.C:
			if NowMS()-conn.lastActiveTime >= 4*1000 {
				conn.close(ErrHeartbeatTimeout)
				return
			}

			conn.heartbeat()
		}
	}
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

			conn.lastActiveTime = NowMS()
			conn.handleRecvedData(buffer[:n])
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

	conn.closed.Store(false)
	conn.kcp = gokcp.NewKCP(convID, conn.onKCPDataOutput)
	conn.kcp.SetBufferReserved(int(PacketHeaderLen))
	conn.kcp.SetNoDelay(true, 10, 2, true)

	return conn
}

func NewConn(conn net.PacketConn, addr net.Addr, handler ConnHandler) *Conn {
	return newConn(atomic.AddUint32(&ConvID, 1), conn, addr, nil, handler)
}
