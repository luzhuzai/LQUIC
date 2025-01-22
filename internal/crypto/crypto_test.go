package crypto

import (
	"crypto/tls"
	"testing"
)

func TestNewCryptoSetup(t *testing.T) {
	// 创建TLS配置
	tlsConfig := &tls.Config{}

	// 创建CryptoSetup实例
	cs := NewCryptoSetup(tlsConfig)

	// 验证初始状态
	if cs.tlsConfig != tlsConfig {
		t.Error("TLS配置设置错误")
	}
	if cs.level != LevelInitial {
		t.Errorf("初始加密级别错误，期望%v，实际%v", LevelInitial, cs.level)
	}
	if cs.handshakeComplete {
		t.Error("初始握手状态应为false")
	}
	if len(cs.handshakeData) != 0 {
		t.Error("初始握手数据应为空")
	}
}

func TestHandleCryptoFrame(t *testing.T) {
	cs := NewCryptoSetup(nil)

	// 测试处理Initial级别数据
	data := []byte("test data")
	err := cs.HandleCryptoFrame(data, LevelInitial)
	if err != nil {
		t.Errorf("处理Initial级别数据失败: %v", err)
	}

	// 验证数据是否正确保存
	if string(cs.handshakeData) != string(data) {
		t.Errorf("握手数据保存错误，期望%v，实际%v", data, cs.handshakeData)
	}

	// 测试处理过期的加密级别
	cs.level = LevelHandshake
	err = cs.HandleCryptoFrame(data, LevelInitial)
	if err == nil {
		t.Error("处理过期加密级别应该返回错误")
	}
}

func TestSetHandshakeComplete(t *testing.T) {
	cs := NewCryptoSetup(nil)

	// 设置握手完成
	cs.SetHandshakeComplete()

	// 验证状态
	if !cs.handshakeComplete {
		t.Error("握手完成状态设置失败")
	}
	if cs.level != LevelOneRTT {
		t.Errorf("握手完成后加密级别错误，期望%v，实际%v", LevelOneRTT, cs.level)
	}
}

func TestHandshakeComplete(t *testing.T) {
	cs := NewCryptoSetup(nil)

	// 初始状态应为未完成
	if cs.HandshakeComplete() {
		t.Error("初始握手状态应为false")
	}

	// 设置完成状态
	cs.SetHandshakeComplete()

	// 验证状态
	if !cs.HandshakeComplete() {
		t.Error("握手完成状态获取错误")
	}
}

func TestGetCurrentLevel(t *testing.T) {
	cs := NewCryptoSetup(nil)

	// 验证初始级别
	if cs.GetCurrentLevel() != LevelInitial {
		t.Errorf("初始加密级别错误，期望%v，实际%v", LevelInitial, cs.GetCurrentLevel())
	}

	// 设置握手完成，验证级别变化
	cs.SetHandshakeComplete()
	if cs.GetCurrentLevel() != LevelOneRTT {
		t.Errorf("握手完成后加密级别错误，期望%v，实际%v", LevelOneRTT, cs.GetCurrentLevel())
	}
}

func TestGetCryptoData(t *testing.T) {
	cs := NewCryptoSetup(nil)

	// 测试各个加密级别的数据生成
	tests := []struct {
		level    CryptoLevel
		expected string
	}{
		{LevelInitial, "initial_handshake_data"},
		{LevelHandshake, "handshake_data"},
		{LevelOneRTT, "one_rtt_data"},
		{CryptoLevel(99), ""}, // 无效的加密级别
	}

	for _, tt := range tests {
		data := cs.GetCryptoData(tt.level)
		if string(data) != tt.expected {
			t.Errorf("加密级别%v的数据错误，期望%v，实际%v", tt.level, tt.expected, string(data))
		}
	}
}
