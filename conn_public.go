package gouxp

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"github.com/shaoyuan1943/gouxp/dh64"

	"github.com/shaoyuan1943/gokcp"
)

// ClientConn
func (conn *ClientConn) UseCryptoCodec(cryptoType CryptoType) {
	conn.Lock()
	defer conn.Unlock()

	conn.cryptoCodec = createCryptoCodec(cryptoType)
}

func (conn *ClientConn) Start() error {
	var handshakeBuffer [handshakeBufferSize]byte
	binary.LittleEndian.PutUint16(handshakeBuffer[macSize:], uint16(protoTypeHandshake))
	binary.LittleEndian.PutUint32(handshakeBuffer[PacketHeaderSize:], conn.convID)

	if conn.cryptoCodec != nil {
		conn.cryptoKeys.privateKey, conn.cryptoKeys.publicKey = dh64.KeyPair()
		binary.LittleEndian.PutUint64(handshakeBuffer[PacketHeaderSize+4:], conn.cryptoKeys.publicKey)
	}

	cipherData, err := conn.encrypt(handshakeBuffer[:])
	if err != nil {
		return err
	}

	_, err = conn.rwc.WriteTo(cipherData, conn.addr)
	if err != nil {
		return err
	}

	go conn.readRawDataLoop()
	return nil
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

// ClientConn end

// RawConn
func (conn *RawConn) EnableFEC() {
	conn.Lock()
	defer conn.Unlock()

	if conn.fecEncoder != nil && conn.fecDecoder != nil {
		return
	}

	conn.fecEncoder = NewFecEncoder(FECDataShards, FECParityShards, int(conn.kcp.MTU())+fecHeaderSize)
	conn.fecDecoder = NewFecDecoder(FECDataShards, FECParityShards, int(conn.kcp.MTU())+fecHeaderSize)
}

// For use KCP status:
// Need To inject Logger object into gouxp
func (conn *RawConn) StartKCPStatus() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		conn.kcpStatus = &gokcp.KCPStatus{}
		conn.stopKCPStatusC = make(chan struct{})

		for {
			select {
			case <-conn.stopKCPStatusC:
				return
			case <-conn.closeC:
				return
			case <-ticker.C:
				conn.Lock()
				conn.kcp.Snapshot(conn.kcpStatus)
				conn.Unlock()
				logKCPStatus(conn.ID(), conn.kcpStatus)
			}
		}
	}()
}

func (conn *RawConn) StopKCPStatus() {
	if conn.stopKCPStatusC != nil {
		close(conn.stopKCPStatusC)
		conn.stopKCPStatusC = nil
		conn.kcpStatus = nil
	}
}

func (conn *RawConn) ID() uint32 {
	return conn.kcp.ConvID()
}

func (conn *RawConn) SetConnHandler(handler ConnHandler) {
	conn.Lock()
	defer conn.Unlock()

	conn.handler = handler
}

// MUST invoke before start
func (conn *RawConn) SetWindow(sndWnd, rcvWnd int) {
	conn.Lock()
	defer conn.Unlock()

	conn.kcp.SetWndSize(sndWnd, rcvWnd)
}

// MUST invoke before start
func (conn *RawConn) SetMTU(mtu int) bool {
	conn.Lock()
	defer conn.Unlock()

	if mtu >= maxDataLengthLimit {
		return false
	}

	result := conn.kcp.SetMTU(mtu)
	if !result {
		return false
	}

	result = conn.kcp.SetBufferReserved(int(PacketHeaderSize))
	if !result {
		return false
	}

	return true
}

// MUST invoke before start
func (conn *RawConn) SetUpdateInterval(interval int) {
	conn.Lock()
	defer conn.Unlock()

	conn.kcp.SetInterval(interval)
}

func (conn *RawConn) IsClosed() bool {
	return conn.closed.Load().(bool) == true
}

func (conn *RawConn) Close() {
	conn.close(nil)
}

func (conn *RawConn) Write(data []byte) (int, error) {
	if conn.IsClosed() {
		return 0, ErrConnClosed
	}

	n := len(data)
	if n > maxDataLengthLimit {
		return 0, ErrWriteDataTooLong
	}

	conn.Lock()
	defer conn.Unlock()

	waitSend := conn.kcp.WaitSend()
	if waitSend < int(conn.kcp.SendWnd()) && waitSend < int(conn.kcp.RemoteWnd()) {
		err := conn.kcp.Send(data)
		if err != nil {
			return 0, err
		}

		return n, nil
	}

	return 0, ErrTryAgain
}

// RawConn end
