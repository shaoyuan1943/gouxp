# gouxp
[![Powered][2]][1]

[1]: https://github.com/skywind3000/kcp
[2]: https://raw.githubusercontent.com/skywind3000/kcp/master/kcp.svg

基于[gokcp](https://github.com/shaoyuan1943/gokcp)开箱即用的可靠UDP传输协议开发包。

### 如何使用
请参考**sample/template**目录下client和server代码示例。  

## 技术特性
### 1. gouxp托管原始PacketConn对象
无论客户端或服务端，在创建PacketConn对象后交由gouxp托管，在托管之前PacketConn可按照自有方式进行收发，托管之后的收发以及关闭均由gouxp控制。

### 2. 以回调方式将数据返回用户层（应用层）
用户层对于gouxp的交互方式为接口回调（参见`interface.go`），之所以采用回调，主要考虑是简单且减少与gouxp不必要的交互。用户只需要关注PacketConn关闭了（`OnClosed`）、有数据来了（`OnNewDataComing`）这两个事件即可。

### 3. 读写分离
PacketConn的读写与KCP的读写由两个goroutinue负责，PacketConn的读写阻塞不影响KCP的读写。

### 4. 内置完整Chacha20poly1305和Salas20加解密
使用Chacha20ploy1305和Salas20算法对数据进行加解密，握手阶段交互双方密钥。gouxp数据包中预留了数据校验mac，默认的mac空位放在数据包头，但ChaCha20poly1305的校验mac是放在数据包末尾，因此使用Chacha20ploy1305加密时，会预先将预留的mac空位移动到末尾，会有额外一次copy的开销，而Salas20的校验mac空位是放在数据包头，对性能敏感的地方需要谨慎考虑。  

### 5. FEC支持
gouxp支持FEC（前向纠错），在公网上（典型场景如移动网络）减少包重传。

## 接口
#### NewServer(rwc net.PacketConn, handler ServerHandler, parallelCount uint32) *Server
新建一个Server，rwc通过net.ListenUDP产生，handler为事件回调，parallelCount为执行所有ServerConn kcp.Update的goroutine数目，过小可能会导致CPU占用偏高，推荐值2、4、6。  

#### func (s *Server) UseCryptoCodec(cryptoType CryptoType)
Server端使用何种加解密方式。  

#### func (s *Server) Close()
手动关闭Server，此函数将会关闭所有服务端连接，不可重用。  

#### func (s *Server) Start()
Server端开始工作，进入UDP读状态。  

#### NewClientConn(rwc net.PacketConn, addr net.Addr, handler ConnHandler) *ClientConn
新建一个Client，rwc通过net.ListenUDP产生，addr为远端地址，handler为事件回调。  

#### func (conn *ClientConn) UseCryptoCodec(cryptoType CryptoType)
Client端使用何种加解密方式。  

#### func (conn *ClientConn) Start() error 
Client端开始工作，按照gouxp工作流程，会先发送握手数据包，等待Server端的握手回包，交换加解密公钥，此后Server端和Client端开始正常的业务通信。  

#### func (conn *RawConn) EnableFEC()
开启FEC。  

#### func (conn *RawConn) ID() uint32
返回当前链接对应的会话ID。  

#### func (conn *RawConn) SetWindow(sndWnd, rcvWnd int)
设置发送窗口大小和接收窗口大小，可以简单理解为TCP的SND_BUF和RCV_BUF，这里的单位是个数，默认为32，建议以32的倍数扩增。  

#### func (conn *RawConn) SetMTU(mtu int) bool
设置传输路径MTU。   

#### func (conn *RawConn) SetUpdateInterval(interval int) 
设置KCP状态循环间隔，推荐值为5ms、10ms、15ms。  

#### func (conn *RawConn) IsClosed() bool
链接是否已经关闭。  

#### func (conn *RawConn) Close()
手动关闭链接。  

#### func (conn *RawConn) Write(data []byte) (int, error)
向远端发送数据，可能返回的错误有ErrDataLenInvalid和ErrTryAgain，前者可能data长度非法，后者是因为等待发送的数据包过多。    

#### func (conn *RawConn) StartKCPStatus()
KCP状态输出，需要向gouxp注入Logger对象，以5秒定时向日志输出当前Conn对应的KCP状态，方便调试，后面会以HTTP方式提供此调试服务。  

#### func (conn *RawConn) StopKCPStatus()
停止KCP状态输出。  

#### func SetDebugLogger(l Logger)
向gouxp注入Logger对象。  


## Q&A
1. 单次最大发送数据是多少？  
对于使用UDP传输协议而言，单次传输的数据应尽量不要超过网络路径MTU，但也不应过低。在gouxp中，用户逻辑数据最大大小`(KCP.MTU() - PacketHeaderSize - KCPHeader - FECHeader)`。默认情况下，`PacketHeaderSize`长度为18，其中为16字节的`mac`，2字节的协议类型；`KCPHeader`为24字节，`FECHeader`为8字节，其中前4个字节为FEC数据包序号，2个字节为FEC数据包类型，最后2个字节为上层数据包长度。

2. 由于UDP面向无连接，如何模拟TCP的连接与断开方便应用层逻辑上的接入？  
首先，限与UDP的特性，无法准确感知UDP的连接与断开，所以在调用ClientConn.Start时，会向服务端发送握手协议，服务端回发握手协议并交换双方公钥，此过程结束之后代表双方可以开始正常通信。其次，ClientConn与ServerConn均使用了心跳检测机制，客户端在握手成功之后，每3秒会向服务端发送心跳数据包，心跳检测周期为3秒，两端均可在心跳过期之后“关闭”连接。


## 参考
* https://github.com/skywind3000/kcp