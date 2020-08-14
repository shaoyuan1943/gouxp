package gouxp

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"github.com/shaoyuan1943/gouxp/dh64"

	"github.com/shaoyuan1943/gokcp"
)

type CryptoKeys struct {
	privateKey uint64
	publicKey  uint64
}

type ClientConn struct {
	RawConn
	convID         uint32
	lastActiveTime int64
	cryptoKeys     CryptoKeys
}

func (conn *ClientConn) close(err error) {
	if atomic.LoadUint32(&conn.closed) == 1 {
		return
	}

	close(conn.closeC)
	conn.rwc.Close()
	atomic.StoreUint32(&conn.closed, 1)
	conn.handler.OnClosed(err)
}

func (conn *ClientConn) Start() error {
	var handshakeBuffer [handshakeBufferSize]byte
	binary.LittleEndian.PutUint16(handshakeBuffer[macSize:], uint16(protoTypeHandshake))
	binary.LittleEndian.PutUint32(handshakeBuffer[PacketHeaderSize:], conn.convID)

	if conn.cryptoCodec != nil {
		conn.cryptoKeys.privateKey, conn.cryptoKeys.publicKey = dh64.KeyPair()
		binary.LittleEndian.PutUint64(handshakeBuffer[PacketHeaderSize+4:], conn.cryptoKeys.publicKey)
	}

	_, err := conn.rwc.WriteTo(handshakeBuffer[:], conn.addr)
	if err != nil {
		return err
	}

	return nil
}

func (conn *ClientConn) onHeartbeat(data []byte) {

}

func (conn *ClientConn) onHandshake(data []byte) {
	if conn.cryptoCodec != nil {
		serverPublicKey := binary.LittleEndian.Uint64(data)
		num := dh64.Secret(conn.cryptoKeys.privateKey, serverPublicKey)
		var nonce [8]byte
		binary.LittleEndian.PutUint64(nonce[:], num)
		conn.cryptoCodec.SetReadNonce(nonce[:])
		conn.cryptoCodec.SetWriteNonce(nonce[:])
	}

	conn.handler.OnReady()
}

func (conn *ClientConn) onKCPData(data []byte) {
	err := conn.kcp.Input(data)
	if err != nil {
		conn.close(err)
		return
	}
}

func (conn *ClientConn) onRecvRawData(data []byte) {
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
		conn.onHandshake(data)
	} else if protoType == protoTypeHeartbeat {
		conn.onHeartbeat(data)
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

func (conn *ClientConn) heartbeatLoop() {
	heartbeatTicker := time.NewTicker(2 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-conn.closeC:
			return
		case <-heartbeatTicker.C:
			if NowMS()-conn.lastActiveTime >= 3*1000 {
				conn.close(ErrHeartbeatTimeout)
				return
			}

			conn.heartbeat()
		}
	}
}

func (conn *ClientConn) readRawDataLoop() {
	buffer := make([]byte, gokcp.KCP_MTU_DEF)
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
			if n > 0 {
				conn.onRecvRawData(buffer[:n])
			}
		}
	}
}

func (conn *ClientConn) heartbeat() {
	if conn.IsClosed() {
		return
	}

	var heartbearBuffer [PacketHeaderSize + 4]byte
	binary.LittleEndian.PutUint16(heartbearBuffer[macSize:], uint16(protoTypeHeartbeat))
	binary.LittleEndian.PutUint32(heartbearBuffer[PacketHeaderSize:], uint32(NowMS()))
	if conn.cryptoCodec != nil {
		_, err := conn.cryptoCodec.Encrypto(heartbearBuffer[:])
		if err != nil {
			conn.close(err)
			return
		}
	}

	conn.write(heartbearBuffer[:])
}

func NewClientConn(rwc net.PacketConn, addr net.Addr, handler ConnHandler) *ClientConn {
	conn := &ClientConn{}
	conn.convID = atomic.AddUint32(&ConvID, 1)
	conn.rwc = rwc
	conn.addr = addr
	conn.handler = handler
	conn.closeC = make(chan struct{})

	conn.kcp = gokcp.NewKCP(conn.convID, conn.onKCPDataOutput)
	conn.kcp.SetBufferReserved(int(PacketHeaderSize))
	conn.kcp.SetNoDelay(true, 10, 2, true)

	return conn
}
