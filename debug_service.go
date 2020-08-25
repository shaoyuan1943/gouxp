package gouxp

import "github.com/shaoyuan1943/gokcp"

var logContents = `
kcp: %v
SendUNA: %v, SendNext: %v, RecvNext: %v,
LastACK: %v, Threshold: %v, RTO: %v,
FastResendACL: %v, FastACKLimit: %v, 
SendWnd: %v, RecvWnd: %v, RemoteWnd: %v, Wnd: %v,
SendQueueLen: %v, SendBufferLen: %v, RecvQueueLen: %v, RecvBufferLen: %v, ACKListLen: %v, Incr: %v
`

func logKCPStatus(convID uint32, status *gokcp.KCPStatus) {
	if logger != nil {
		logger.Debugf(logContents, convID, status.SendUNA, status.SendNext, status.RecvNext, status.LastACK,
			status.Threshold, status.RTO, status.FastResendACK, status.FastACKLimit,
			status.SendWnd, status.RecvWnd, status.RemoteWnd, status.Wnd,
			status.SendQueueLen, status.SendBufferLen, status.RecvQueueLen, status.RecvBufferLen,
			status.ACKListLen, status.Incr)
	}
}
