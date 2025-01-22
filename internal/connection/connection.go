// Package connection 实现QUIC连接管理相关功能
package connection

import (
	"fmt"
	"net"
	"sync"

	"LQUIC/internal/crypto"
	"LQUIC/internal/flowcontrol"
	"LQUIC/internal/packet"
	"LQUIC/internal/protocol"
)

// ConnectionState 表示连接状态
type ConnectionState int

const (
	// StateInitial 初始状态
	StateInitial ConnectionState = iota
	// StateHandshaking 握手中
	StateHandshaking
	// StateEstablished 已建立
	StateEstablished
	// StateClosed 已关闭
	StateClosed
)

// Connection 表示一个QUIC连接
type Connection struct {
	// 连接状态
	state      ConnectionState
	stateMutex sync.RWMutex

	// 连接标识
	destConnID protocol.ConnectionID
	srcConnID  protocol.ConnectionID

	// 网络相关
	remoteAddr *net.UDPAddr
	conn       *net.UDPConn

	// 加密相关
	cryptoSetup *crypto.CryptoSetup

	// 流量控制
	flowController *flowcontrol.FlowController

	// 数据包处理
	packetNumberGenerator protocol.PacketNumber // 用于生成递增的数据包序号
	packetNumberMux       sync.Mutex            // 保护包序号生成器的互斥锁

	// 关闭相关
	closeChan chan struct{}
	closeOnce sync.Once
}

// GetDestConnID 返回目标连接ID
func (c *Connection) GetDestConnID() protocol.ConnectionID {
	return c.destConnID
}

// GetSrcConnID 返回源连接ID
func (c *Connection) GetSrcConnID() protocol.ConnectionID {
	return c.srcConnID
}

// NewConnection 创建新的QUIC连接
func NewConnection(destConnID, srcConnID protocol.ConnectionID, remoteAddr *net.UDPAddr, conn *net.UDPConn, cryptoSetup *crypto.CryptoSetup) *Connection {
	// 设置默认的初始窗口大小
	initialWindowSize := flowcontrol.WindowSize(1048576) // 1MB
	maxWindowSize := flowcontrol.WindowSize(16777216)    // 16MB

	return &Connection{
		state:          StateInitial,
		destConnID:     destConnID,
		srcConnID:      srcConnID,
		remoteAddr:     remoteAddr,
		conn:           conn,
		cryptoSetup:    cryptoSetup,
		flowController: flowcontrol.NewFlowController(initialWindowSize, maxWindowSize),
		closeChan:      make(chan struct{}),
	}
}

// GetState 获取连接状态
func (c *Connection) GetState() ConnectionState {
	c.stateMutex.RLock()
	defer c.stateMutex.RUnlock()
	return c.state
}

// setState 设置连接状态
func (c *Connection) setState(state ConnectionState) {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()
	c.state = state
}

// generatePacketNumber 生成新的数据包序号
func (c *Connection) generatePacketNumber() protocol.PacketNumber {
	c.packetNumberMux.Lock()
	defer c.packetNumberMux.Unlock()
	c.packetNumberGenerator++
	return c.packetNumberGenerator
}

// validatePacketNumber 验证数据包序号的有效性
func (c *Connection) validatePacketNumber(receivedPN protocol.PacketNumber) bool {
	c.packetNumberMux.Lock()
	defer c.packetNumberMux.Unlock()
	// 检查接收到的包序号是否大于当前最大包序号
	return receivedPN > c.packetNumberGenerator
}

// HandlePacket 处理接收到的数据包
func (c *Connection) HandlePacket(p *packet.Packet) error {
	// 验证数据包序号
	if !c.validatePacketNumber(p.Header.PacketNumber) {
		return fmt.Errorf("无效的数据包序号: %d", p.Header.PacketNumber)
	}

	switch p.Header.Type {
	case protocol.PacketTypeInitial:
		return c.handleInitialPacket(p)
	case protocol.PacketTypeHandshake:
		return c.handleHandshakePacket(p)
	case protocol.PacketTypeOneRTT:
		return c.handleOneRTTPacket(p)
	default:
		return nil
	}
}

// handleInitialPacket 处理Initial数据包
func (c *Connection) handleInitialPacket(p *packet.Packet) error {
	// 验证版本
	if p.Header.Version != protocol.Version {
		return fmt.Errorf("不支持的QUIC版本: %d", p.Header.Version)
	}

	// 处理加密握手数据
	if err := c.cryptoSetup.HandleCryptoFrame(p.Payload, crypto.LevelInitial); err != nil {
		return fmt.Errorf("处理Initial加密数据失败: %v", err)
	}

	// 更新连接状态
	if c.GetState() == StateInitial {
		c.setState(StateHandshaking)
	}

	return nil
}

// handleHandshakePacket 处理Handshake数据包
func (c *Connection) handleHandshakePacket(p *packet.Packet) error {
	// 处理握手数据
	if err := c.cryptoSetup.HandleCryptoFrame(p.Payload, crypto.LevelHandshake); err != nil {
		return fmt.Errorf("处理Handshake加密数据失败: %v", err)
	}

	// 检查握手是否完成
	if c.cryptoSetup.HandshakeComplete() {
		c.setState(StateEstablished)
		c.cryptoSetup.SetHandshakeComplete()
	}

	return nil
}

// handleOneRTTPacket 处理1-RTT数据包
func (c *Connection) handleOneRTTPacket(p *packet.Packet) error {
	// 检查连接状态
	if c.GetState() != StateEstablished {
		return fmt.Errorf("连接未建立，无法处理1-RTT数据包")
	}

	// 检查流量控制
	if !c.flowController.CanSend(protocol.ByteCount(len(p.Payload))) {
		return fmt.Errorf("超出流量控制窗口限制")
	}

	// 更新流量控制
	c.flowController.OnDataSent(protocol.ByteCount(len(p.Payload)))

	// 处理应用层数据
	if len(p.Payload) > 0 {
		// 根据QUIC协议规范处理应用层数据
		// 1. 验证数据完整性
		if !c.cryptoSetup.HandshakeComplete() {
			return fmt.Errorf("加密握手未完成，无法处理应用层数据")
		}

		// 2. 处理数据帧
		// 这里可以根据实际应用协议进行扩展
		// 例如：HTTP/3、WebSocket等

		// 3. 更新接收窗口
		c.flowController.UpdateWindow(protocol.ByteCount(len(p.Payload)))
	}

	return nil
}

// Close 关闭连接
func (c *Connection) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeChan)
		c.setState(StateClosed)
	})
	return nil
}
