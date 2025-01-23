// Package client 实现QUIC客户端功能
package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"LQUIC/internal/connection"
	"LQUIC/internal/crypto"
	"LQUIC/internal/packet"
	"LQUIC/internal/protocol"
)

// Config 客户端配置
type Config struct {
	RemoteAddr string
	TLSConfig  *tls.Config
}

// Client QUIC客户端
type Client struct {
	config Config
	conn   *net.UDPConn
	// 连接管理
	connection    *connection.Connection
	connectionMux sync.RWMutex
	// 加密设置
	cryptoSetup *crypto.CryptoSetup
	// 连接ID生成器
	idGenerator *connection.IDGenerator
	// 关闭通道
	closeChan chan struct{}
}

// New 创建新的QUIC客户端
func New(config Config) (*Client, error) {
	return &Client{
		config:      config,
		idGenerator: connection.NewIDGenerator(connection.IDLength),
		closeChan:   make(chan struct{}),
		cryptoSetup: crypto.NewCryptoSetup(config.TLSConfig),
	}, nil
}

// Connect 连接到服务器
func (c *Client) Connect() error {
	addr, err := net.ResolveUDPAddr("udp", c.config.RemoteAddr)
	if err != nil {
		return fmt.Errorf("解析地址失败: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("连接服务器失败: %v", err)
	}
	c.conn = conn

	// 生成连接ID
	destConnID, err := c.idGenerator.GenerateConnectionID()
	if err != nil {
		return fmt.Errorf("生成连接ID失败: %v", err)
	}

	// 发送初始数据包
	err = c.sendInitialPacket(destConnID)
	if err != nil {
		return fmt.Errorf("发送初始数据包失败: %v", err)
	}

	go c.readLoop()
	return nil
}

// sendInitialPacket 发送初始数据包
func (c *Client) sendInitialPacket(destConnID protocol.ConnectionID) error {
	// 创建初始数据包
	p := &packet.Packet{
		Header: packet.Header{
			Type:         protocol.PacketTypeInitial,
			Version:      protocol.Version,
			DestConnID:   destConnID,
			PacketNumber: 0,
		},
		Payload: c.cryptoSetup.GetCryptoData(crypto.LevelInitial), // 添加初始握手数据
	}

	// 序列化数据包
	data, err := p.Pack()
	if err != nil {
		return err
	}

	// 发送数据包
	_, err = c.conn.Write(data)
	return err
}

// readLoop 读取数据包
func (c *Client) readLoop() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-c.closeChan:
			return
		default:
			n, _, err := c.conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			go c.handlePacket(buf[:n])
		}
	}
}

// handlePacket 处理接收到的数据包
func (c *Client) handlePacket(data []byte) {
	// 解析数据包
	p, err := packet.Unpack(data)
	if err != nil {
		return
	}

	// 处理握手和加密
	switch p.Header.Type {
	case protocol.PacketTypeInitial:
		c.handleInitialResponse(p)
	case protocol.PacketTypeHandshake:
		c.handleHandshakeResponse(p)
	case protocol.PacketTypeOneRTT:
		c.handleOneRTTPacket(p)
	}
}

// handleInitialResponse 处理初始响应数据包
func (c *Client) handleInitialResponse(p *packet.Packet) {
	// 处理服务器的Initial包
	if err := c.cryptoSetup.HandleCryptoFrame(p.Payload, crypto.LevelInitial); err != nil {
		return
	}

	// 更新连接状态
	c.connectionMux.Lock()
	if c.connection == nil {
		c.connection = connection.NewConnection(
			p.Header.DestConnID,
			p.Header.SrcConnID,
			c.conn.RemoteAddr().(*net.UDPAddr),
			c.conn,
			c.cryptoSetup,
		)
	}
	c.connectionMux.Unlock()
}

// handleHandshakeResponse 处理握手响应数据包
func (c *Client) handleHandshakeResponse(p *packet.Packet) {
	// 处理服务器的Handshake包
	if err := c.cryptoSetup.HandleCryptoFrame(p.Payload, crypto.LevelHandshake); err != nil {
		return
	}

	// 如果握手完成，更新加密状态
	if c.cryptoSetup.HandshakeComplete() {
		c.cryptoSetup.SetHandshakeComplete()
	}
}

// handleOneRTTPacket 处理1-RTT数据包
func (c *Client) handleOneRTTPacket(p *packet.Packet) {
	c.connectionMux.RLock()
	defer c.connectionMux.RUnlock()

	if c.connection == nil {
		return
	}

	// 将数据包交给连接处理
	c.connection.HandlePacket(p)
}

// Close 关闭客户端
func (c *Client) Close() error {
	close(c.closeChan)
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
