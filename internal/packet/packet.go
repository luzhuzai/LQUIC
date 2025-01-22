// Package packet 实现QUIC数据包的封装和解析
package packet

import (
	"encoding/binary"
	"fmt"

	"LQUIC/internal/protocol"
)

// Header 表示QUIC数据包头部
type Header struct {
	Type         protocol.PacketType
	Version      uint32
	DestConnID   protocol.ConnectionID
	SrcConnID    protocol.ConnectionID
	PacketNumber protocol.PacketNumber
	PayloadLen   protocol.ByteCount
}

// Pack 将Header序列化为字节流
func (h *Header) Pack() ([]byte, error) {
	// 验证包类型
	switch h.Type {
	case protocol.PacketTypeInitial,
		protocol.PacketTypeHandshake,
		protocol.PacketTypeOneRTT,
		protocol.PacketTypeRetry:
		// 有效的包类型
	default:
		return nil, fmt.Errorf("无效的包类型: %d", h.Type)
	}

	// 预分配足够的空间
	buf := make([]byte, 0, 1500) // 常见MTU大小

	// 写入包类型
	buf = append(buf, byte(h.Type))

	// 写入版本号
	versionBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBuf, h.Version)
	buf = append(buf, versionBuf...)

	// 写入目标连接ID
	buf = append(buf, byte(len(h.DestConnID)))
	buf = append(buf, h.DestConnID...)

	// 写入源连接ID
	buf = append(buf, byte(len(h.SrcConnID)))
	buf = append(buf, h.SrcConnID...)

	// 写入包序号
	pnBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(pnBuf, uint64(h.PacketNumber))
	buf = append(buf, pnBuf...)

	return buf, nil
}

// Unpack 从字节流解析Header
func (h *Header) Unpack(data []byte) error {
	if len(data) < 22 { // 最小包头长度
		return fmt.Errorf("数据包太短")
	}

	var offset int

	// 解析包类型
	h.Type = protocol.PacketType(data[0])
	offset++

	// 解析版本号
	h.Version = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// 解析目标连接ID
	destConnIDLen := int(data[offset])
	offset++
	if offset+destConnIDLen > len(data) {
		return fmt.Errorf("数据包截断：目标连接ID")
	}
	h.DestConnID = protocol.ConnectionID(data[offset : offset+destConnIDLen])
	offset += destConnIDLen

	// 解析源连接ID
	srcConnIDLen := int(data[offset])
	offset++
	if offset+srcConnIDLen > len(data) {
		return fmt.Errorf("数据包截断：源连接ID")
	}
	h.SrcConnID = protocol.ConnectionID(data[offset : offset+srcConnIDLen])
	offset += srcConnIDLen

	// 解析包序号
	if offset+8 > len(data) {
		return fmt.Errorf("数据包截断：包序号")
	}
	h.PacketNumber = protocol.PacketNumber(binary.BigEndian.Uint64(data[offset:]))

	return nil
}

// Packet 表示完整的QUIC数据包
type Packet struct {
	Header  Header
	Payload []byte
}

// Pack 将数据包序列化为字节流
func (p *Packet) Pack() ([]byte, error) {
	// 验证包类型
	switch p.Header.Type {
	case protocol.PacketTypeInitial,
		protocol.PacketTypeHandshake,
		protocol.PacketTypeOneRTT,
		protocol.PacketTypeRetry:
		// 有效的包类型
	default:
		return nil, fmt.Errorf("无效的包类型: %d", p.Header.Type)
	}

	// 预分配足够的空间
	buf := make([]byte, 0, 1500) // 常见MTU大小

	// 写入包类型
	buf = append(buf, byte(p.Header.Type))

	// 写入版本号
	versionBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBuf, p.Header.Version)
	buf = append(buf, versionBuf...)

	// 写入目标连接ID
	buf = append(buf, byte(len(p.Header.DestConnID)))
	buf = append(buf, p.Header.DestConnID...)

	// 写入源连接ID
	buf = append(buf, byte(len(p.Header.SrcConnID)))
	buf = append(buf, p.Header.SrcConnID...)

	// 写入包序号
	pnBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(pnBuf, uint64(p.Header.PacketNumber))
	buf = append(buf, pnBuf...)

	// 写入负载长度
	lenBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBuf, uint64(len(p.Payload)))
	buf = append(buf, lenBuf...)

	// 写入负载
	buf = append(buf, p.Payload...)

	return buf, nil
}

// Unpack 从字节流解析数据包
func Unpack(data []byte) (*Packet, error) {
	if len(data) < 22 { // 最小包头长度
		return nil, fmt.Errorf("数据包太短")
	}

	var offset int
	packet := &Packet{}

	// 解析包类型
	packet.Header.Type = protocol.PacketType(data[0])
	offset++

	// 解析版本号
	packet.Header.Version = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// 解析目标连接ID
	destConnIDLen := int(data[offset])
	offset++
	if offset+destConnIDLen > len(data) {
		return nil, fmt.Errorf("数据包截断：目标连接ID")
	}
	packet.Header.DestConnID = protocol.ConnectionID(data[offset : offset+destConnIDLen])
	offset += destConnIDLen

	// 解析源连接ID
	srcConnIDLen := int(data[offset])
	offset++
	if offset+srcConnIDLen > len(data) {
		return nil, fmt.Errorf("数据包截断：源连接ID")
	}
	packet.Header.SrcConnID = protocol.ConnectionID(data[offset : offset+srcConnIDLen])
	offset += srcConnIDLen

	// 解析包序号
	if offset+8 > len(data) {
		return nil, fmt.Errorf("数据包截断：包序号")
	}
	packet.Header.PacketNumber = protocol.PacketNumber(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	// 解析负载长度
	if offset+8 > len(data) {
		return nil, fmt.Errorf("数据包截断：负载长度")
	}
	payloadLen := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// 解析负载
	if offset+int(payloadLen) > len(data) {
		return nil, fmt.Errorf("数据包截断：负载")
	}
	packet.Payload = data[offset : offset+int(payloadLen)]

	return packet, nil
}
