package gouxp

import (
	"encoding/binary"
	"time"

	"github.com/shaoyuan1943/gokcp"
)

type ServerConn struct {
	RawConn
	convID            uint32
	server            *Server
	lastHeartbeatTime uint32
}

func (conn *ServerConn) onHandshaked() {
	go func() {
		checkHeartbeatTicker := time.NewTicker(2 * time.Second)
		defer checkHeartbeatTicker.Stop()

		for {
			select {
			case <-conn.closeC:
				return
			case <-checkHeartbeatTicker.C:
				conn.locker.Lock()
				if gokcp.SetupFromNowMS()-conn.lastHeartbeatTime > 3*1000 {
					conn.locker.Unlock()
					conn.close(ErrHeartbeatTimeout)
					return
				}
				conn.locker.Unlock()
			}
		}
	}()

	conn.update()
}

func (conn *ServerConn) update() {
	if conn.IsClosed() {
		return
	}

	conn.locker.Lock()
	err := conn.sendAndRecvFromKCP()
	if err != nil {
		conn.locker.Unlock()
		conn.close(err)
		return
	}

	conn.kcp.Update()
	nextTime := conn.kcp.Check()
	conn.locker.Unlock()
	conn.server.scheduler.PushTask(conn.update, nextTime)
}

// response
func (conn *ServerConn) onHeartbeat(data []byte) {
	conn.lastHeartbeatTime = gokcp.SetupFromNowMS()

	var heartbeatRspBuffer [PacketHeaderSize + 4]byte
	binary.LittleEndian.PutUint16(heartbeatRspBuffer[macSize:], uint16(protoTypeHeartbeat))
	binary.LittleEndian.PutUint32(heartbeatRspBuffer[macSize+2:], gokcp.SetupFromNowMS())

	conn.locker.Lock()
	if conn.cryptoCodec != nil {
		_, err := conn.cryptoCodec.Encrypto(heartbeatRspBuffer[:])
		if err != nil {
			conn.locker.Unlock()
			conn.close(err)
			return
		}
	}
	conn.locker.Unlock()

	err := conn.write(heartbeatRspBuffer[:])
	if err != nil {
		conn.close(err)
	}
}

func (conn *ServerConn) close(err error) {
	if conn.IsClosed() {
		return
	}

	conn.locker.Lock()
	defer conn.locker.Unlock()

	conn.closed.Store(true)
	close(conn.closeC)
	conn.server.removeConnection(conn)
	conn.handler.OnClosed(err)
}
