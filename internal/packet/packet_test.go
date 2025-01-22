package packet

import (
	"bytes"
	"testing"

	"LQUIC/internal/protocol"
)

func TestHeaderPackUnpack(t *testing.T) {
	// 创建测试用的Header
	original := Header{
		Type:         protocol.PacketTypeInitial,
		Version:      protocol.Version,
		DestConnID:   protocol.ConnectionID{1, 2, 3, 4},
		SrcConnID:    protocol.ConnectionID{5, 6, 7, 8},
		PacketNumber: 1,
	}

	// 序列化Header
	data, err := original.Pack()
	if err != nil {
		t.Fatalf("序列化Header失败: %v", err)
	}

	// 反序列化Header
	var unpacked Header
	err = unpacked.Unpack(data)
	if err != nil {
		t.Fatalf("反序列化Header失败: %v", err)
	}

	// 验证字段值
	if unpacked.Type != original.Type {
		t.Errorf("Type不匹配，期望%v，实际%v", original.Type, unpacked.Type)
	}
	if unpacked.Version != original.Version {
		t.Errorf("Version不匹配，期望%v，实际%v", original.Version, unpacked.Version)
	}
	if !bytes.Equal(unpacked.DestConnID, original.DestConnID) {
		t.Errorf("DestConnID不匹配，期望%v，实际%v", original.DestConnID, unpacked.DestConnID)
	}
	if !bytes.Equal(unpacked.SrcConnID, original.SrcConnID) {
		t.Errorf("SrcConnID不匹配，期望%v，实际%v", original.SrcConnID, unpacked.SrcConnID)
	}
	if unpacked.PacketNumber != original.PacketNumber {
		t.Errorf("PacketNumber不匹配，期望%v，实际%v", original.PacketNumber, unpacked.PacketNumber)
	}
}

func TestPacketPackUnpack(t *testing.T) {
	// 创建测试用的Packet
	original := &Packet{
		Header: Header{
			Type:         protocol.PacketTypeInitial,
			Version:      protocol.Version,
			DestConnID:   protocol.ConnectionID{1, 2, 3, 4},
			SrcConnID:    protocol.ConnectionID{5, 6, 7, 8},
			PacketNumber: 1,
		},
		Payload: []byte("test payload"),
	}

	// 序列化Packet
	data, err := original.Pack()
	if err != nil {
		t.Fatalf("序列化Packet失败: %v", err)
	}

	// 反序列化Packet
	unpacked, err := Unpack(data)
	if err != nil {
		t.Fatalf("反序列化Packet失败: %v", err)
	}

	// 验证Header
	if unpacked.Header.Type != original.Header.Type {
		t.Errorf("Header.Type不匹配，期望%v，实际%v", original.Header.Type, unpacked.Header.Type)
	}
	if unpacked.Header.Version != original.Header.Version {
		t.Errorf("Header.Version不匹配，期望%v，实际%v", original.Header.Version, unpacked.Header.Version)
	}
	if !bytes.Equal(unpacked.Header.DestConnID, original.Header.DestConnID) {
		t.Errorf("Header.DestConnID不匹配，期望%v，实际%v", original.Header.DestConnID, unpacked.Header.DestConnID)
	}
	if !bytes.Equal(unpacked.Header.SrcConnID, original.Header.SrcConnID) {
		t.Errorf("Header.SrcConnID不匹配，期望%v，实际%v", original.Header.SrcConnID, unpacked.Header.SrcConnID)
	}
	if unpacked.Header.PacketNumber != original.Header.PacketNumber {
		t.Errorf("Header.PacketNumber不匹配，期望%v，实际%v", original.Header.PacketNumber, unpacked.Header.PacketNumber)
	}

	// 验证Payload
	if !bytes.Equal(unpacked.Payload, original.Payload) {
		t.Errorf("Payload不匹配，期望%v，实际%v", original.Payload, unpacked.Payload)
	}
}

func TestInvalidPacket(t *testing.T) {
	// 测试空数据
	_, err := Unpack(nil)
	if err == nil {
		t.Error("期望解析空数据返回错误，但没有")
	}

	// 测试无效的数据包类型
	invalidPacket := &Packet{
		Header: Header{
			Type: 255, // 无效的包类型
		},
	}
	_, err = invalidPacket.Pack()
	if err == nil {
		t.Error("期望序列化无效包类型返回错误，但没有")
	}
}
