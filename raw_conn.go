package gouxp

import (
	"net"
	"sync/atomic"

	"github.com/shaoyuan1943/gokcp"
)

type RawConn struct {
	kcp         *gokcp.KCP
	addr        net.Addr
	rwc         net.PacketConn
	outPackets  [][]byte
	cryptoCodec CryptoCodec
	handler     ConnHandler
	closeC      chan struct{}
	closed      uint32
	iAmLeavingC chan *RawConn
}

func (conn *RawConn) SetCryptoCodec(cryptoCodec CryptoCodec) {
	if cryptoCodec != nil {
		conn.cryptoCodec = cryptoCodec
	}
}

func (conn *RawConn) IsClosed() bool {
	return atomic.LoadUint32(&conn.closed) == 1
}

func (conn *RawConn) Close() {
	conn.close(nil)
}

func (conn *RawConn) close(err error) {
	if atomic.LoadUint32(&conn.closed) == 1 {
		return
	}

	close(conn.closeC)
	conn.rwc.Close()
	atomic.StoreUint32(&conn.closed, 1)
	conn.handler.OnClosed(err)

	if conn.iAmLeavingC != nil {
		conn.iAmLeavingC <- conn
	}
}

func (conn *RawConn) write(data []byte) {
	_, err := conn.rwc.WriteTo(data, conn.addr)
	if err != nil {
		conn.close(err)
		return
	}
}

func (conn *RawConn) Write(data []byte) {
	// TODO: need locker
	conn.outPackets = append(conn.outPackets, data)
}

func (conn *RawConn) onKCPDataComing(data []byte) error {
	return conn.kcp.Input(data)
}

func (conn *RawConn) onKCPDataOutput(data []byte) {
	if conn.cryptoCodec != nil {
		cryptoBuffer, err := conn.cryptoCodec.Encrypto(data)
		if err != nil {
			conn.close(err)
			return
		}

		data = cryptoBuffer
	}

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
		outPackets = append(outPackets, conn.outPackets...)
		conn.outPackets = conn.outPackets[:0]

		for _, packet := range outPackets {
			err := conn.kcp.Send(packet)
			if err != nil {
				conn.close(err)
				return false
			}
		}
	}

	// KCP.Recv
	buffer := make([]byte, conn.kcp.Mtu())
	if !conn.kcp.IsStreamMode() {
		if size := conn.kcp.PeekSize(); size > 0 {
			n, err := conn.kcp.Recv(buffer)
			if err != nil {
				conn.close(err)
				return false
			}

			conn.handler.OnNewDataComing(buffer[:n])
		}
	} else {
		for {
			if size := conn.kcp.PeekSize(); size > 0 {
				n, err := conn.kcp.Recv(buffer)
				if err != nil {
					conn.close(err)
					return false
				}

				conn.handler.OnNewDataComing(buffer[:n])
			} else {
				break
			}
		}
	}

	return true
}
