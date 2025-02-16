package crypto

import (
	"bytes"
	"crypto/rand"
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
	if len(cs.sessionTicket) != 0 {
		t.Error("初始会话票据应为空")
	}
	if len(cs.zeroRTTKey) != 0 {
		t.Error("初始0-RTT密钥应为空")
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
	if !bytes.Equal(cs.handshakeData, data) {
		t.Errorf("握手数据保存错误，期望%v，实际%v", data, cs.handshakeData)
	}

	// 测试处理过期的加密级别
	cs.level = LevelHandshake
	err = cs.HandleCryptoFrame(data, LevelInitial)
	if err == nil {
		t.Error("处理过期加密级别应该返回错误")
	}

	// 测试追加数据
	newData := []byte("additional data")
	err = cs.HandleCryptoFrame(newData, LevelHandshake)
	if err != nil {
		t.Errorf("追加握手数据失败: %v", err)
	}

	expectedData := append(data, newData...)
	if !bytes.Equal(cs.handshakeData, expectedData) {
		t.Errorf("握手数据追加错误，期望%v，实际%v", expectedData, cs.handshakeData)
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
	// 创建带有TLS配置的CryptoSetup实例
	tlsConfig := &tls.Config{
		ClientSessionCache: tls.NewLRUClientSessionCache(10),
		Rand:               rand.Reader,
	}
	cs := NewCryptoSetup(tlsConfig)

	// 测试无效的TLS配置
	cs.tlsConfig = nil
	if data := cs.GetCryptoData(LevelInitial); data != nil {
		t.Error("无效TLS配置应返回nil")
	}

	// 恢复TLS配置
	cs.tlsConfig = tlsConfig

	// 测试初始密钥生成
	initialData := cs.GetCryptoData(LevelInitial)
	if initialData == nil {
		t.Error("初始密钥生成失败")
	}

	// 测试握手密钥生成（数据不足）
	if data := cs.GetCryptoData(LevelHandshake); data != nil {
		t.Error("握手数据不足时应返回nil")
	}

	// 设置足够的握手数据
	cs.handshakeData = make([]byte, 64)
	handshakeData := cs.GetCryptoData(LevelHandshake)
	if handshakeData == nil {
		t.Error("握手密钥生成失败")
	}

	// 测试应用数据密钥生成（握手未完成）
	if data := cs.GetCryptoData(LevelOneRTT); data != nil {
		t.Error("握手未完成时应返回nil")
	}

	// 完成握手并设置足够的数据
	cs.handshakeData = make([]byte, 96)
	cs.SetHandshakeComplete()
	appData := cs.GetCryptoData(LevelOneRTT)
	if appData == nil {
		t.Error("应用数据密钥生成失败")
	}

	// 测试无效的加密级别
	if data := cs.GetCryptoData(CryptoLevel(99)); data != nil {
		t.Error("无效加密级别应返回nil")
	}
}

func TestUpdateSessionTicket(t *testing.T) {
	cs := NewCryptoSetup(nil)

	// 测试握手未完成时更新会话票据
	ticket := []byte("test ticket")
	err := cs.UpdateSessionTicket(ticket)
	if err == nil {
		t.Error("握手未完成时应返回错误")
	}

	// 完成握手
	cs.SetHandshakeComplete()

	// 测试更新会话票据
	err = cs.UpdateSessionTicket(ticket)
	if err != nil {
		t.Errorf("更新会话票据失败: %v", err)
	}
	if !bytes.Equal(cs.sessionTicket, ticket) {
		t.Errorf("会话票据设置错误，期望%v，实际%v", ticket, cs.sessionTicket)
	}
}

func TestCompleteOneRTT(t *testing.T) {
	// 创建带有TLS配置的CryptoSetup实例
	tlsConfig := &tls.Config{
		ClientSessionCache: tls.NewLRUClientSessionCache(10),
		Rand:               rand.Reader,
	}
	cs := NewCryptoSetup(tlsConfig)

	// 测试无效的TLS配置
	cs.tlsConfig = nil
	_, err := cs.CompleteOneRTT()
	if err == nil {
		t.Error("无效TLS配置应返回错误")
	}

	// 恢复TLS配置
	cs.tlsConfig = tlsConfig

	// 设置握手数据并完成握手
	cs.handshakeData = make([]byte, 96)
	cs.SetHandshakeComplete()

	// 测试完成1-RTT握手
	ticket, err := cs.CompleteOneRTT()
	if err != nil {
		t.Errorf("完成1-RTT握手失败: %v", err)
	}
	if len(ticket) == 0 {
		t.Error("生成的会话票据不应为空")
	}

	// 验证会话票据的有效性
	if len(ticket) != 32 {
		t.Errorf("会话票据长度错误，期望32字节，实际%d字节", len(ticket))
	}

	// 验证可以使用生成的会话票据进行0-RTT
	success, key := cs.TryZeroRTT(ticket)
	if !success {
		t.Error("使用有效会话票据应返回true")
	}
	if key == nil {
		t.Error("使用有效会话票据应返回非nil密钥")
	}
}

func TestTryZeroRTT(t *testing.T) {
	cs := NewCryptoSetup(nil)

	// 测试无效的票据ID
	success, key := cs.TryZeroRTT(nil)
	if success {
		t.Error("无效票据ID应返回false")
	}
	if key != nil {
		t.Error("无效票据ID应返回nil密钥")
	}

	// 设置握手数据
	cs.handshakeData = []byte("test handshake data")

	// 测试有效的票据ID
	success, key = cs.TryZeroRTT([]byte("test id"))
	if !success {
		t.Error("有效票据ID应返回true")
	}
	if key == nil {
		t.Error("有效票据ID应返回非nil密钥")
	}
}

func TestSetZeroRTTKey(t *testing.T) {
	cs := NewCryptoSetup(nil)

	// 测试设置无效的密钥
	if err := cs.SetZeroRTTKey(nil); err == nil {
		t.Error("设置无效密钥应返回错误")
	}

	// 测试设置有效的密钥
	key := []byte("test key")
	if err := cs.SetZeroRTTKey(key); err != nil {
		t.Errorf("设置有效密钥失败: %v", err)
	}
	if !bytes.Equal(cs.zeroRTTKey, key) {
		t.Errorf("0-RTT密钥设置错误，期望%v，实际%v", key, cs.zeroRTTKey)
	}
}
