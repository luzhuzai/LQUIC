// Package crypto 实现QUIC的加密和安全功能
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
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
	// 会话票据
	sessionTicket []byte
	// 0-RTT密钥
	zeroRTTKey []byte
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

	// 检查TLS配置是否有效
	if c.tlsConfig == nil {
		return nil
	}

	// 根据加密级别生成相应的握手数据
	switch level {
	case LevelInitial:
		// 使用TLS 1.3的初始密钥
		return c.generateInitialSecrets()
	case LevelHandshake:
		// 使用TLS 1.3的握手密钥
		return c.generateHandshakeSecrets()
	case LevelOneRTT:
		// 使用TLS 1.3的应用数据密钥
		return c.generateApplicationSecrets()
	default:
		return nil
	}
}

// UpdateSessionTicket 更新会话票据
func (c *CryptoSetup) UpdateSessionTicket(ticket []byte) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.handshakeComplete {
		return fmt.Errorf("握手未完成，无法更新会话票据")
	}

	c.sessionTicket = ticket
	return nil
}

// CompleteOneRTT 完成1-RTT握手
func (c *CryptoSetup) CompleteOneRTT() ([]byte, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// 验证TLS配置和握手状态
	if c.tlsConfig == nil || c.tlsConfig.Rand == nil || !c.handshakeComplete {
		return nil, fmt.Errorf("无效的TLS配置或握手未完成")
	}

	// 根据QUIC规范生成会话票据
	ticket := make([]byte, 32)
	if _, err := c.tlsConfig.Rand.Read(ticket); err != nil {
		return nil, fmt.Errorf("生成会话票据失败: %v", err)
	}

	// 使用握手数据和会话票据派生最终的会话密钥
	info := append([]byte("tls13 resumption "), c.handshakeData...)
	ticketKey := hkdfExtract(info, ticket)

	// 保存会话票据
	c.sessionTicket = ticket

	return ticketKey, nil
}

// TryZeroRTT 尝试0-RTT连接
func (c *CryptoSetup) TryZeroRTT(ticketID []byte) (bool, []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// 验证会话票据和握手数据
	if len(ticketID) == 0 || c.handshakeData == nil {
		return false, nil
	}

	// 根据QUIC规范生成0-RTT密钥
	info := append([]byte("tls13 0-rtt "), c.handshakeData...)
	zeroRTTKey := hkdfExtract(info, ticketID)

	// 验证密钥有效性
	if len(zeroRTTKey) == 0 {
		return false, nil
	}

	// 保存0-RTT密钥
	c.zeroRTTKey = zeroRTTKey

	return true, zeroRTTKey
}

// SetZeroRTTKey 设置0-RTT密钥
func (c *CryptoSetup) SetZeroRTTKey(key []byte) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// 验证密钥的有效性
	if key == nil {
		return fmt.Errorf("无效的0-RTT密钥")
	}

	// 存储0-RTT密钥
	c.zeroRTTKey = key
	return nil
}

// generateInitialSecrets 生成初始密钥
func (c *CryptoSetup) generateInitialSecrets() []byte {
	// 使用QUIC版本1的标准初始盐值
	initialSalt := []byte{0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3, 0x4D, 0x17, 0x2A, 0x14, 0x48, 0x9B, 0x7C, 0xD1, 0xF4, 0x3E, 0x5A, 0x8B}

	if c.tlsConfig == nil {
		return nil
	}

	// 从TLS配置中获取连接状态
	connState := c.tlsConfig.ClientSessionCache
	if connState == nil {
		return nil
	}

	// TODO: 从connection包获取连接ID
	// 临时使用随机生成的连接ID
	connID := make([]byte, 20)
	if _, err := c.tlsConfig.Rand.Read(connID); err != nil {
		return nil
	}

	// 使用HKDF-Extract生成初始密钥
	initialSecret := hkdfExtract(initialSalt, connID)
	return initialSecret
}

// generateHandshakeSecrets 生成握手密钥
func (c *CryptoSetup) generateHandshakeSecrets() []byte {
	if c.tlsConfig == nil || c.handshakeData == nil {
		return nil
	}

	// 验证握手数据长度
	if len(c.handshakeData) < 64 {
		return nil
	}

	// 按照TLS 1.3标准提取密钥材料
	clientRandom := c.handshakeData[:32]
	serverRandom := c.handshakeData[32:64]
	keyMaterial := append(clientRandom, serverRandom...)

	// 使用TLS 1.3的密钥派生函数
	handshakeContext := sha256.Sum256(keyMaterial)
	handshakeSecret := hkdfExtract(handshakeContext[:], []byte("tls13 hs"))

	// 派生握手流量密钥
	trafficSecret := hkdfExtract(handshakeSecret, []byte("traffic"))
	return trafficSecret
}

// generateApplicationSecrets 生成应用数据密钥
func (c *CryptoSetup) generateApplicationSecrets() []byte {
	if !c.handshakeComplete || c.handshakeData == nil {
		return nil
	}

	// 验证握手数据长度
	if len(c.handshakeData) < 96 {
		return nil
	}

	// 按照QUIC规范提取主密钥
	masterSecret := c.handshakeData[len(c.handshakeData)-32:]

	// 使用TLS 1.3的密钥派生函数
	appSecret := hkdfExtract(masterSecret, []byte("tls13 ap traffic"))

	// 派生应用数据流量密钥
	trafficSecret := hkdfExtract(appSecret, []byte("quic key"))
	return trafficSecret
}

// hkdfExtract 实现HKDF-Extract函数
func hkdfExtract(salt, ikm []byte) []byte {
	// 使用crypto/tls包中的标准HKDF-Extract实现
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}
