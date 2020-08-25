package gouxp

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shaoyuan1943/gokcp"
)

type closer interface {
	close(err error)
}

type RawConn struct {
	closer
	kcp            *gokcp.KCP
	addr           net.Addr
	rwc            net.PacketConn
	outPackets     [][]byte
	packetsLen     int
	cryptoCodec    CryptoCodec
	handler        ConnHandler
	closeC         chan struct{}
	closed         atomic.Value
	locker         sync.Mutex
	kcpStatus      *gokcp.KCPStatus
	stopKCPStatusC chan struct{}
}

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
				conn.locker.Lock()
				conn.kcp.Snapshot(conn.kcpStatus)
				conn.locker.Unlock()
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
	conn.locker.Lock()
	defer conn.locker.Unlock()

	conn.handler = handler
}

// SetWindow\SetMTU\SetUpdateInterval\SetUpdateInterval
// MUST invoke before start!
func (conn *RawConn) SetWindow(sndWnd, rcvWnd int) {
	conn.locker.Lock()
	defer conn.locker.Unlock()

	conn.kcp.SetWndSize(sndWnd, rcvWnd)
}

func (conn *RawConn) SetMTU(mtu int, reserved int) bool {
	conn.locker.Lock()
	defer conn.locker.Unlock()

	if mtu >= int(MaxBufferSize) {
		return false
	}

	return conn.kcp.SetMTU(mtu, reserved)
}

func (conn *RawConn) SetUpdateInterval(interval int) {
	conn.locker.Lock()
	defer conn.locker.Unlock()

	conn.kcp.SetInterval(interval)
}

func (conn *RawConn) SetCryptoCodec(cryptoCodec CryptoCodec) {
	conn.locker.Lock()
	defer conn.locker.Unlock()

	conn.cryptoCodec = cryptoCodec
}

func (conn *RawConn) IsClosed() bool {
	return conn.closed.Load().(bool) == true
}

func (conn *RawConn) Close() {
	conn.close(nil)
}

func (conn *RawConn) write(data []byte) error {
	_, err := conn.rwc.WriteTo(data, conn.addr)
	return err
}

func (conn *RawConn) Write(data []byte) (n int, err error) {
	if conn.IsClosed() {
		return
	}

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
	if conn.IsClosed() {
		return
	}

	binary.LittleEndian.PutUint16(data[macSize:], uint16(protoTypeData))
	if conn.cryptoCodec != nil {
		cipherData, err := conn.cryptoCodec.Encrypto(data)
		if err != nil {
			go func() {
				conn.close(err)
			}()

			return
		}

		data = cipherData
	}

	err := conn.write(data)
	if err != nil {
		go func() {
			conn.close(err)
		}()
	}
}

func (conn *RawConn) rwUpdate() error {
	// KCP.Send
	waitSend := conn.kcp.WaitSend()
	if waitSend < int(conn.kcp.SendWnd()) && waitSend < int(conn.kcp.RemoteWnd()) && conn.packetsLen > 0 {
		var outPackets [][]byte
		outPackets = append(outPackets, conn.outPackets...)
		conn.outPackets = conn.outPackets[:0]
		conn.packetsLen = 0

		for _, packet := range outPackets {
			err := conn.kcp.Send(packet)
			if err != nil {
				return err
			}
		}
	}

	// KCP.Recv
	buffer := make([]byte, conn.kcp.Mtu())
	if !conn.kcp.IsStreamMode() {
		if size := conn.kcp.PeekSize(); size > 0 {
			n, err := conn.kcp.Recv(buffer)
			if err != nil {
				return err
			}

			conn.handler.OnNewDataComing(buffer[:n])
		}
	} else {
		for {
			if size := conn.kcp.PeekSize(); size > 0 {
				n, err := conn.kcp.Recv(buffer)
				if err != nil {
					return err
				}

				conn.handler.OnNewDataComing(buffer[:n])
			} else {
				break
			}
		}
	}

	return nil
}
