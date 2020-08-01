package gouxp

type ServerHandler interface {
	OnNewClientComing(conn *Conn)
	OnClosed(err error)
}

type ConnHandler interface {
	OnClosed(err error)
	OnSendDataError(data []byte, err error)
	OnNewDataComing(data []byte)
}
