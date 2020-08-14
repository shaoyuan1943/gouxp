package gouxp

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/shaoyuan1943/gokcp"
)

type closer interface {
	close(err error)
}

type RawConn struct {
	closer
	kcp         *gokcp.KCP
	addr        net.Addr
	rwc         net.PacketConn
	outPackets  [][]byte
	packetsLen  int
	cryptoCodec CryptoCodec
	handler     ConnHandler
	closeC      chan struct{}
	closed      atomic.Value
	locker      sync.Mutex
}

func (conn *RawConn) SetCryptoCodec(cryptoCodec CryptoCodec) {
	if cryptoCodec != nil {
		conn.cryptoCodec = cryptoCodec
	}
}

func (conn *RawConn) IsClosed() bool {
	return conn.closed.Load().(bool) == true
}

func (conn *RawConn) Close() {
	conn.close(nil)
}

func (conn *RawConn) write(data []byte) {
	_, err := conn.rwc.WriteTo(data, conn.addr)
	if err != nil {
		conn.close(err)
		return
	}
}

func (conn *RawConn) Write(data []byte) (n int, err error) {
	conn.locker.Lock()
	defer conn.locker.Unlock()

	n = len(data)
	if conn.packetsLen+n > 65535 { // 64k
		n = 0
		err = ErrTryAgain
		return
	}

	conn.outPackets = append(conn.outPackets, data)
	conn.packetsLen += n
	return n, nil
}

func (conn *RawConn) onKCPDataInput(data []byte) {
	conn.locker.Lock()
	err := conn.kcp.Input(data)
	if err != nil {
		conn.locker.Unlock()
		conn.close(err)
		return
	}
	conn.locker.Unlock()
}

func (conn *RawConn) onKCPDataOutput(data []byte) {
	conn.locker.Lock()
	if conn.cryptoCodec != nil {
		cryptoBuffer, err := conn.cryptoCodec.Encrypto(data)
		if err != nil {
			conn.locker.Unlock()
			conn.close(err)
			return
		}

		data = cryptoBuffer
	}
	conn.locker.Unlock()

	_, err := conn.rwc.WriteTo(data, conn.addr)
	if err != nil {
		conn.close(err)
		return
	}
}

func (conn *RawConn) rwUpdate() bool {
	// KCP.Send
	waitSend := conn.kcp.WaitSend()
	if waitSend < int(conn.kcp.SendWnd()) && waitSend < int(conn.kcp.RemoteWnd()) {
		var outPackets [][]byte
		conn.locker.Lock()
		outPackets = append(outPackets, conn.outPackets...)
		conn.outPackets = conn.outPackets[:0]
		conn.packetsLen = 0
		conn.locker.Unlock()

		for _, packet := range outPackets {
			err := conn.kcp.Send(packet)
			if err != nil {
				conn.close(err)
				return false
			}
		}
	}

	// KCP.Recv
	conn.locker.Lock()
	buffer := make([]byte, conn.kcp.Mtu())
	if !conn.kcp.IsStreamMode() {
		if size := conn.kcp.PeekSize(); size > 0 {
			n, err := conn.kcp.Recv(buffer)
			if err != nil {
				conn.locker.Unlock()
				conn.close(err)
				return false
			}

			conn.handler.OnNewDataComing(buffer[:n])
			conn.locker.Unlock()
		}
	} else {
		for {
			if size := conn.kcp.PeekSize(); size > 0 {
				n, err := conn.kcp.Recv(buffer)
				if err != nil {
					conn.locker.Unlock()
					conn.close(err)
					return false
				}

				conn.handler.OnNewDataComing(buffer[:n])
				conn.locker.Unlock()
			} else {
				conn.locker.Unlock()
				break
			}
		}
	}

	return true
}
