package gouxp

import (
	"encoding/binary"
	"time"
)

type ServerConn struct {
	RawConn
	convID            uint32
	server            *Server
	lastHeartbeatTime int64
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
				if NowMS()-conn.lastHeartbeatTime > 3*1000 {
					conn.locker.Unlock()
					conn.close(ErrHeartbeatTimeout)
					return
				}
				conn.locker.Unlock()
			default:
				conn.rwUpdate()
			}
		}
	}()

	conn.updateKCP()
}

func (conn *ServerConn) updateKCP() {
	if conn.IsClosed() {
		return
	}

	conn.locker.Lock()
	defer conn.locker.Unlock()

	conn.kcp.Update()
	nextTime := conn.kcp.Check()
	conn.server.scheduler.PushTask(conn.updateKCP, nextTime)
}

// response
func (conn *ServerConn) onHeartbeat(data []byte) {
	conn.lastHeartbeatTime = NowMS()

	var heartbeatRspBuffer [PacketHeaderSize + 4]byte
	binary.LittleEndian.PutUint16(heartbeatRspBuffer[macSize:], uint16(protoTypeHeartbeat))
	binary.LittleEndian.PutUint32(heartbeatRspBuffer[macSize+2:], uint32(NowMS()))

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

	conn.write(heartbeatRspBuffer[:])
}

func (conn *ServerConn) close(err error) {
	if conn.IsClosed() {
		return
	}

	conn.locker.Lock()
	defer conn.locker.Unlock()

	close(conn.closeC)
	conn.closed.Store(true)
	conn.handler.OnClosed(err)

	go func() {
		conn.server.notifyConnHasGone(conn)
	}()
}
