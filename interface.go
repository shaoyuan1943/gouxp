package gouxp

type ServerHandler interface {
	OnNewClientComing(conn *ServerConn)
	OnClosed(err error)
}

type ConnHandler interface {
	OnClosed(err error)
	OnNewDataComing(data []byte)
	OnReady()
}
