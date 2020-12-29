package gouxp

import (
	"encoding/binary"
	"errors"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/shaoyuan1943/gokcp"
)

type ServerConn struct {
	RawConn
	convID uint32
	server *Server
}

func (conn *ServerConn) onHandshake() {
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
	defer func() {
		if r := recover(); r != nil {
			var stackBuffer [4096]byte
			n := runtime.Stack(stackBuffer[:], false)
			if logger != nil {
				logger.Errorf("server conn exit from panic: %v", stackBuffer[:n])
			}

			conn.close(errors.New("server conn exit from panic"))
		}
	}()

	if conn.IsClosed() {
		return
	}

	var err error
	defer func() {
		conn.Unlock()
		if err != nil {
			conn.close(err)
		}
	}()

	conn.Lock()

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
	var heartbeatBuffer [heartbeatBufferSize]byte
	binary.LittleEndian.PutUint16(heartbeatBuffer[macSize:], uint16(protoTypeHeartbeat))
	binary.LittleEndian.PutUint32(heartbeatBuffer[PacketHeaderSize:], gokcp.SetupFromNowMS())

	conn.Lock()
	defer conn.Unlock()

	cipherData, err := conn.encrypt(heartbeatBuffer[:])
	if err != nil {
		return err
	}

	return conn.write(cipherData)
}

func (conn *ServerConn) close(err error) {
	if conn.IsClosed() {
		return
	}

	conn.Lock()
	defer conn.Unlock()

	close(conn.closeC)
	conn.server.removeConnection(conn)
	conn.handler.OnClosed(err)
	conn.server.handler.OnConnClosed(conn, err)
	conn.closed.Store(true)
}
