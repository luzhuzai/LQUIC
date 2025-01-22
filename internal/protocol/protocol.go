// Package protocol 定义QUIC协议的基本常量和类型
package protocol

// Version 定义QUIC版本号
const Version = uint32(1)

// ConnectionID 表示QUIC连接ID
type ConnectionID []byte

// PacketType 定义QUIC数据包类型
type PacketType uint8

const (
	// PacketTypeInitial 初始数据包
	PacketTypeInitial PacketType = iota + 1
	// PacketTypeHandshake 握手数据包
	PacketTypeHandshake
	// PacketTypeOneRTT 1-RTT数据包
	PacketTypeOneRTT
	// PacketTypeRetry 重试数据包
	PacketTypeRetry
)

// StreamID 表示QUIC流ID
type StreamID uint64

// ByteCount 表示字节计数
type ByteCount uint64

// PacketNumber 表示数据包编号
type PacketNumber uint64
