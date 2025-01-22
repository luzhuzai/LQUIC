package protocol

import (
	"testing"
)

func TestConnectionID(t *testing.T) {
	// 测试空的ConnectionID
	var emptyID ConnectionID
	if len(emptyID) != 0 {
		t.Errorf("空ConnectionID长度应为0，实际为%d", len(emptyID))
	}

	// 测试有效的ConnectionID
	id := ConnectionID{1, 2, 3, 4}
	if len(id) != 4 {
		t.Errorf("ConnectionID长度应为4，实际为%d", len(id))
	}

	// 测试ConnectionID的比较
	id2 := ConnectionID{1, 2, 3, 4}
	if string(id) != string(id2) {
		t.Error("相同内容的ConnectionID应该相等")
	}
}

func TestPacketType(t *testing.T) {
	// 测试所有数据包类型的值
	tests := []struct {
		name     string
		pType    PacketType
		expected PacketType
	}{
		{"Initial包类型", PacketTypeInitial, 1},
		{"Handshake包类型", PacketTypeHandshake, 2},
		{"OneRTT包类型", PacketTypeOneRTT, 3},
		{"Retry包类型", PacketTypeRetry, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.pType != tt.expected {
				t.Errorf("%s值错误，期望%d，实际%d", tt.name, tt.expected, tt.pType)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	// 测试版本号常量
	if Version != 1 {
		t.Errorf("Version值错误，期望1，实际%d", Version)
	}
}

func TestStreamID(t *testing.T) {
	// 测试StreamID类型
	var sid StreamID = 1
	if sid != 1 {
		t.Errorf("StreamID值错误，期望1，实际%d", sid)
	}
}

func TestByteCount(t *testing.T) {
	// 测试ByteCount类型
	var count ByteCount = 1024
	if count != 1024 {
		t.Errorf("ByteCount值错误，期望1024，实际%d", count)
	}
}

func TestPacketNumber(t *testing.T) {
	// 测试PacketNumber类型
	var pn PacketNumber = 100
	if pn != 100 {
		t.Errorf("PacketNumber值错误，期望100，实际%d", pn)
	}
}
