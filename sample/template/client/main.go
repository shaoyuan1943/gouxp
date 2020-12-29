package main

import (
	"net"

	"github.com/shaoyuan1943/gouxp"
)

type Client struct {
	*gouxp.ClientConn
}

func (client *Client) OnClosed(err error)          {}
func (client *Client) OnNewDataComing(data []byte) {}
func (client *Client) OnReady()                    {}

func main() {
	addr := "127.0.0.1:9000"
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return
	}

	client := &Client{}
	client.ClientConn = gouxp.NewClientConn(conn, udpAddr, client, 16836) // bufferLen: 16K
	// client.SetMTU
	// client.SetUpdateInterval
	// client.SetWindow
	// client.UseCryptoCodec
	// client.EnableFEC
	client.Start()

	// client.Close
	return
}
