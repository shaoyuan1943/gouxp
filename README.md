# gouxp
基于[gokcp](https://github.com/shaoyuan1943/gokcp)开箱即用的可靠UDP传输协议开发包。

### 如何使用
客户端：
``` go
type Client struct {
    conn *gouxp.ClientConn
}

// PacketConn关闭
func (client *Client) OnClosed(err error) {
}
// 有数据抵达，解密之后的数据
func (client *Client) OnNewDataComing(data []byte) {
}
// 与gouxp服务端握手结束
func (client *Client) OnReady() {
}

udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9007")
if err != nil {
    return
}

conn, err := net.ListenUDP("udp", nil)
if err != nil {
    return
}

client := &Client{}
client.conn = gouxp.NewClientConn(conn, udpAddr, client)
client.conn.Start()

// Write
client.conn.Write([]byte("Hello World"))
```

服务端：
``` go
type Client struct {
	conn *gouxp.ServerConn
}

func (client *Client) OnClosed(err error) {
}

func (client *Client) OnNewDataComing(data []byte) {
}

func (client *Client) OnReady() {
}

type MyServer struct {
	conn       *gouxp.Server
	allClients []*Client
}

func (server *MyServer) OnNewClientComing(conn *gouxp.ServerConn) {
	client := &Client{
		conn: conn,
	}

	client.conn.SetConnHandler(client)
	server.allClients = append(server.allClients, client)
    // 开启KCP状态数据输出，需要注入Logger接口对象
    //client.conn.StartKCPStatus()
}

func (server *MyServer) OnClosed(err error) {
}

func NewMyServer(addr string) *MyServer {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil
	}

	s := &MyServer{}
	s.conn = gouxp.NewServer(conn, s, 2)
	return s
}

server := NewMyServer("0.0.0.0:9007")
server.conn.Start()
```

## 技术特性
### 1. gouxp托管原始PacketConn对象
无论客户端或服务端，在创建PacketConn对象后交由gouxp托管，在托管之前PacketConn可按照自有方式进行收发，托管之后的收发以及关闭均有gouxp控制。

### 2. 以回调方式将数据返回用户层（应用层）
用户层对于gouxp的交互方式为接口回调（参见`interface.go`），之所以采用回调，主要考虑是简单，且减少与gouxp不必要的交互。用户只需要关注PacketConn关闭了、有数据来了这两个事件即可。

### 3. PacketConn读与KCP读写分离
PacketConn的读写与KCP的读写有两个goroutinue负责，PacketConn的读写阻塞不影响KCP的读写。

### 4. 内置完整Chacha20poly1305和Salas20加解密
使用Chacha20ploy1305和Salas20算法对数据进行加解密，握手阶段交互双方密钥，使得每一次读写的Nonce都不一样。

### 5. FEC支持
gouxp支持FEC（前向纠错），在公网上（典型场景如移动网络）减少包重传。

## Q&A
1. 单次最大发送数据是多少？  
对于使用UDP传输协议而言，单次传输的数据应尽量不要超过网络路径MTU，但也不应过低，所以在gouxp中，单词传输的最大数据应为`(KCP.Mtu() - PacketHeaderSize)`。

2. 由于UDP面向无连接，如何模拟TCP的连接与断开方便应用层逻辑上的接入？  
首先，限与UDP的特性，无法准确感知UDP的连接与断开，所以在调用ClientConn.Start时，会向服务端发送握手协议，服务端回发握手协议并交换双方公钥，此过程结束之后代表双方可以开始正常通信。其次，ClientConn与ServerConn均使用了心跳检测机制，客户端在握手成功之后，每3秒会向服务端发送心跳数据包，心跳检测周期为3秒，两端均可在心跳过期之后“关闭”连接。

