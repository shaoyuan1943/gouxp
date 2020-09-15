package gouxp

import (
	"encoding/binary"
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
	kcp            *gokcp.KCP
	addr           net.Addr
	rwc            net.PacketConn
	cryptoCodec    CryptCodec
	handler        ConnHandler
	closeC         chan struct{}
	closed         atomic.Value
	locker         sync.Mutex
	kcpStatus      *gokcp.KCPStatus
	stopKCPStatusC chan struct{}
	fecEncoder     *FecCodecEncoder
	fecDecoder     *FecCodecDecoder
	lastActiveTime uint32
}

func (conn *RawConn) encrypt(data []byte) (cipherData []byte, err error) {
	if conn.cryptoCodec != nil {
		cipherData, err = conn.cryptoCodec.Encrypt(data)
		return
	}

	cipherData = data
	err = nil
	return
}

func (conn *RawConn) decrypt(cipherData []byte) (plaintextData []byte, err error) {
	if conn.cryptoCodec != nil {
		plaintextData, err = conn.cryptoCodec.Decrypt(cipherData)
		return
	}

	plaintextData = cipherData[macSize:]
	err = nil
	return
}

func (conn *RawConn) write(data []byte) error {
	_, err := conn.rwc.WriteTo(data, conn.addr)
	return err
}

func (conn *RawConn) onKCPDataInput(data []byte) error {
	conn.locker.Lock()
	defer conn.locker.Unlock()

	return conn.kcp.Input(data)
}

func (conn *RawConn) onKCPDataOutput(data []byte) error {
	binary.LittleEndian.PutUint16(data[macSize:], uint16(protoTypeData))

	cipherData, err := conn.encrypt(data)
	if err != nil {
		return err
	}

	if conn.fecEncoder != nil && conn.fecDecoder != nil {
		fecData, err := conn.fecEncoder.Encode(cipherData)
		if err != nil {
			return err
		}

		if fecData != nil {
			for _, v := range fecData {
				err = conn.write(v)
				if err != nil {
					return err
				}
			}
		}
	} else {
		err = conn.write(cipherData)
		if err != nil {
			return err
		}
	}

	return nil
}

func (conn *RawConn) recvFromKCP() error {
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
