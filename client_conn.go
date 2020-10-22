package gouxp

import (
	"encoding/binary"
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
	convID     uint32
	cryptoKeys CryptoKeys
}

func (conn *ClientConn) close(err error) {
	conn.locker.Lock()
	defer conn.locker.Unlock()

	if conn.IsClosed() {
		return
	}

	conn.rwc.Close()
	close(conn.closeC)

	conn.closed.Store(true)
	conn.handler.OnClosed(err)
}

func (conn *ClientConn) onHeartbeat(data []byte) error {
	return nil
}

func (conn *ClientConn) onHandshake(data []byte) error {
	// 1. exchange public key
	if conn.cryptoCodec != nil {
		serverPublicKey := binary.LittleEndian.Uint64(data)
		num := dh64.Secret(conn.cryptoKeys.privateKey, serverPublicKey)
		var nonce [8]byte
		binary.LittleEndian.PutUint64(nonce[:], num)
		conn.cryptoCodec.SetReadNonce(nonce[:])
		conn.cryptoCodec.SetWriteNonce(nonce[:])
	}

	// 2. send first heartbeat
	err := conn.heartbeat()
	if err != nil {
		return err
	}

	// 3. client handler callback
	conn.handler.OnReady()
	// 4. update KCP
	go conn.update()
	return nil
}

func (conn *ClientConn) update() {
	if conn.IsClosed() {
		return
	}

	updateTicker := time.NewTicker(10 * time.Millisecond)
	defer updateTicker.Stop()

	heartbeatTicker := time.NewTicker(2 * time.Second)
	defer heartbeatTicker.Stop()

	var err error
	defer func() {
		if err != nil {
			conn.close(err)
		}
	}()

	updateHeartbeat := func() error {
		if gokcp.SetupFromNowMS()-atomic.LoadUint32(&conn.lastActiveTime) > 3*1000 {
			return ErrHeartbeatTimeout
		}

		return conn.heartbeat()
	}

	updateKCP := func() error {
		conn.locker.Lock()
		defer conn.locker.Unlock()

		rvErr := conn.recvFromKCP()
		if rvErr != nil {
			return rvErr
		}

		upErr := conn.kcp.Update()
		if upErr != nil {
			return upErr
		}

		return nil
	}

	for {
		if conn.IsClosed() {
			return
		}

		select {
		case <-conn.closeC:
			return
		case <-heartbeatTicker.C:
			err = updateHeartbeat()
			if err != nil {
				return
			}
		case <-updateTicker.C:
			err = updateKCP()
			if err != nil {
				return
			}
		}
	}
}

func (conn *ClientConn) onRecvRawData(data []byte) {
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
			parseErr = conn.onHandshake(logicData)
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
				err = parseData(v)
				if err != nil {
					return
				}
			}
		}
	} else {
		err = parseData(data)
		if err != nil {
			return
		}
	}
}

func (conn *ClientConn) readRawDataLoop() {
	buffer := make([]byte, MaxMTULimit)
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

			atomic.StoreUint32(&conn.lastActiveTime, gokcp.SetupFromNowMS())
			if n > 0 {
				conn.onRecvRawData(buffer[:n])
			}
		}
	}
}

func (conn *ClientConn) heartbeat() error {
	var heartbeatBuffer [heartbeatBufferSize]byte
	binary.LittleEndian.PutUint16(heartbeatBuffer[macSize:], uint16(protoTypeHeartbeat))
	binary.LittleEndian.PutUint32(heartbeatBuffer[PacketHeaderSize:], gokcp.SetupFromNowMS())

	conn.locker.Lock()
	defer conn.locker.Unlock()

	cipherData, err := conn.encrypt(heartbeatBuffer[:])
	if err != nil {
		return err
	}

	return conn.write(cipherData)
}
