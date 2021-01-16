package gouxp

import "github.com/pkg/errors"

var (
	ErrConnClosed          = errors.New("connection is closed")
	ErrDifferentAddr       = errors.New("different remote addr")
	ErrMessageAuthFailed   = errors.New("message authentication failed")
	ErrHeartbeatTimeout    = errors.New("conn heartbeat timeout")
	ErrInvalidNonceSize    = errors.New("invalid nonce size")
	ErrTryAgain            = errors.New("try again")
	ErrWriteDataTooLong    = errors.New("write data too long")
	ErrUnknownProtocolType = errors.New("unknown protocol type")
	ErrExistConnection     = errors.New("exist connection")
)
