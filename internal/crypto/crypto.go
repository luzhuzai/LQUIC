// Package crypto 实现QUIC的加密和安全功能
package crypto

import (
	"crypto/tls"
	"fmt"
	"sync"
)

// CryptoLevel 表示加密级别
type CryptoLevel uint8

const (
	// LevelInitial 初始加密级别
	LevelInitial CryptoLevel = iota
	// LevelHandshake 握手加密级别
	LevelHandshake
	// LevelOneRTT 1-RTT加密级别
	LevelOneRTT
)

// CryptoSetup 管理QUIC连接的加密状态
type CryptoSetup struct {
	mutex sync.RWMutex

	// TLS配置
	tlsConfig *tls.Config
	// 当前加密级别
	level CryptoLevel
	// 是否完成握手
	handshakeComplete bool
	// 握手数据
	handshakeData []byte
}

// NewCryptoSetup 创建新的加密设置
func NewCryptoSetup(tlsConfig *tls.Config) *CryptoSetup {
	return &CryptoSetup{
		tlsConfig: tlsConfig,
		level:     LevelInitial,
	}
}

// HandleCryptoFrame 处理加密帧
func (c *CryptoSetup) HandleCryptoFrame(data []byte, level CryptoLevel) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if level < c.level {
		return fmt.Errorf("收到过期的加密级别数据")
	}

	// 处理握手数据
	c.handshakeData = append(c.handshakeData, data...)
	return nil
}

// SetHandshakeComplete 设置握手完成状态
func (c *CryptoSetup) SetHandshakeComplete() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.handshakeComplete = true
	c.level = LevelOneRTT
}

// HandshakeComplete 检查握手是否完成
func (c *CryptoSetup) HandshakeComplete() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.handshakeComplete
}

// GetCurrentLevel 获取当前加密级别
func (c *CryptoSetup) GetCurrentLevel() CryptoLevel {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.level
}

// GetCryptoData 获取指定加密级别的加密数据
func (c *CryptoSetup) GetCryptoData(level CryptoLevel) []byte {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// 根据加密级别生成相应的握手数据
	switch level {
	case LevelInitial:
		// 生成初始握手数据
		return []byte("initial_handshake_data")
	case LevelHandshake:
		// 生成握手数据
		return []byte("handshake_data")
	case LevelOneRTT:
		// 生成1-RTT数据
		return []byte("one_rtt_data")
	default:
		return nil
	}
}
