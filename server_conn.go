package gouxp

import (
	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/shaoyuan1943/gokcp"
)

type ServerConn struct {
	RawConn
	convID uint32
	server *Server
}

func (conn *ServerConn) onHandshaked() {
	go func() {
		heartbeatTicker := time.NewTicker(2 * time.Second)
		defer heartbeatTicker.Stop()

		for {
			select {
			case <-conn.closeC:
				return
			case <-heartbeatTicker.C:
				if gokcp.SetupFromNowMS()-atomic.LoadUint32(&conn.lastActiveTime) > 3*1000 {
					conn.close(ErrHeartbeatTimeout)
					return
				}
			}
		}
	}()

	conn.update()
}

func (conn *ServerConn) update() {
	if conn.IsClosed() {
		return
	}

	var err error
	defer func() {
		conn.locker.Unlock()
		if err != nil {
			conn.close(err)
		}
	}()

	conn.locker.Lock()
	err = conn.recvFromKCP()
	if err != nil {
		return
	}

	err = conn.kcp.Update()
	if err != nil {
		return
	}

	nextTime := conn.kcp.Check()
	conn.server.scheduler.PushTask(conn.update, nextTime)
}

// response
func (conn *ServerConn) onHeartbeat(data []byte) error {
	var heartbeatRspBuffer [PacketHeaderSize + 4]byte
	binary.LittleEndian.PutUint16(heartbeatRspBuffer[macSize:], uint16(protoTypeHeartbeat))
	binary.LittleEndian.PutUint32(heartbeatRspBuffer[macSize+2:], gokcp.SetupFromNowMS())

	_, err := conn.Write(heartbeatRspBuffer[:])
	return err
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
