package gouxp

type ServerHandler interface {
	OnNewConnComing(conn *ServerConn)
	OnConnClosed(conn *ServerConn, err error)
	OnClosed(err error)
}

type ConnHandler interface {
	OnClosed(err error)
	OnNewDataComing(data []byte)
	OnReady()
}
