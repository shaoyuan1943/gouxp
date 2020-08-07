package gouxp

import "github.com/pkg/errors"

var (
	ErrDifferentAddr     = errors.New("different remote addr.")
	ErrMessageAuthFailed = errors.New("message authentication failed")
	ErrHeartbeatTimeout  = errors.New("conn heartbeat timeout")
	ErrInvalidNonceSize  = errors.New("invalid nonce size")
)
