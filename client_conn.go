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
	cryptoKeys     CryptoKeys
	lastActiveTime uint32
}

func (conn *ClientConn) close(err error) {
	if conn.IsClosed() {
		return
	}

	conn.locker.Lock()
	defer conn.locker.Unlock()

	conn.closed.Store(true)
	close(conn.closeC)
	conn.rwc.Close()
	conn.handler.OnClosed(err)
}

func (conn *ClientConn) Start() error {
	var handshakeBuffer [handshakeBufferSize]byte
	binary.LittleEndian.PutUint16(handshakeBuffer[macSize:], uint16(protoTypeHandshake))
	binary.LittleEndian.PutUint32(handshakeBuffer[PacketHeaderSize:], conn.convID)

	if conn.cryptoCodec != nil {
		conn.cryptoKeys.privateKey, conn.cryptoKeys.publicKey = dh64.KeyPair()
		binary.LittleEndian.PutUint64(handshakeBuffer[PacketHeaderSize+4:], conn.cryptoKeys.publicKey)

		_, err := conn.cryptoCodec.Encrypto(handshakeBuffer[:])
		if err != nil {
			return err
		}
	}

	_, err := conn.rwc.WriteTo(handshakeBuffer[:], conn.addr)
	if err != nil {
		return err
	}

	go conn.readRawDataLoop()
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

	conn.heartbeat()
	conn.handler.OnReady()

	go func() {
		heartbeatTicker := time.NewTicker(2 * time.Second)
		defer heartbeatTicker.Stop()

		updateTicker := time.NewTicker(10 * time.Millisecond)
		defer updateTicker.Stop()

		for {
			select {
			case <-conn.closeC:
				return
			case <-heartbeatTicker.C:
				if gokcp.SetupFromNowMS()-conn.lastActiveTime >= 3*1000 {
					conn.close(ErrHeartbeatTimeout)
					return
				}

				conn.heartbeat()
			case <-updateTicker.C:
				conn.update()
			}
		}
	}()
}

func (conn *ClientConn) update() {
	if conn.IsClosed() {
		return
	}

	conn.locker.Lock()
	err := conn.rwUpdate()
	if err != nil {
		conn.locker.Unlock()
		conn.close(err)
		return
	}

	conn.kcp.Update()
	conn.locker.Unlock()
}

func (conn *ClientConn) onRecvRawData(data []byte) {
	conn.locker.Lock()
	if conn.cryptoCodec != nil {
		plainData, err := conn.cryptoCodec.Decrypto(data)
		if err != nil {
			conn.locker.Unlock()
			conn.close(err)
			return
		}

		data = plainData
	} else {
		data = data[macSize:]
	}
	conn.locker.Unlock()

	protoType := ProtoType(binary.LittleEndian.Uint16(data))
	data = data[protoSize:]
	if protoType == protoTypeHandshake {
		conn.onHandshake(data)
	} else if protoType == protoTypeHeartbeat {
		conn.onHeartbeat(data)
	} else if protoType == protoTypeData {
		conn.onKCPDataInput(data)
	} else {
		// TODO: unknown protocol type
	}
}

func (conn *ClientConn) readRawDataLoop() {
	buffer := make([]byte, MaxBufferSize)
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

			conn.lastActiveTime = gokcp.SetupFromNowMS()
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

	var heartbeatBuffer [heartbeatBufferSize]byte
	binary.LittleEndian.PutUint16(heartbeatBuffer[macSize:], uint16(protoTypeHeartbeat))
	binary.LittleEndian.PutUint32(heartbeatBuffer[PacketHeaderSize:], gokcp.SetupFromNowMS())

	conn.locker.Lock()
	if conn.cryptoCodec != nil {
		_, err := conn.cryptoCodec.Encrypto(heartbeatBuffer[:])
		if err != nil {
			conn.locker.Unlock()
			conn.close(err)
			return
		}
	}
	conn.locker.Unlock()

	err := conn.write(heartbeatBuffer[:])
	if err != nil {
		conn.close(err)
	}
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
	conn.closed.Store(false)
	conn.closer = conn
	return conn
}
