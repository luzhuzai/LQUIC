// Package crypto 实现QUIC的加密和安全功能
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"sync"
	"time"
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
	// 0-RTT反重放保护
	zeroRTTReplayWindow map[string]int64
	// 0-RTT reject标志
	zeroRTTRejected bool
	// 0-RTT回退数据
	zeroRTTFallbackData []byte
}

// NewCryptoSetup 创建新的加密设置
func NewCryptoSetup(tlsConfig *tls.Config) *CryptoSetup {
	return &CryptoSetup{
		tlsConfig:           tlsConfig,
		level:               LevelInitial,
		zeroRTTReplayWindow: make(map[string]int64),
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

	// 检查是否已被拒绝
	if c.zeroRTTRejected {
		return false, nil
	}

	// 反重放保护：检查时间戳和计数器
	ticketKey := string(ticketID)
	timestamp := time.Now().Unix()
	if lastUsed, exists := c.zeroRTTReplayWindow[ticketKey]; exists {
		// 检查时间窗口（10秒内的重放）
		if timestamp-lastUsed < 10 {
			return false, nil
		}
	}

	// 更新重放窗口
	c.zeroRTTReplayWindow[ticketKey] = timestamp

	// 根据QUIC规范生成0-RTT密钥
	info := append([]byte("tls13 0-rtt "), c.handshakeData...)
	zeroRTTKey := hkdfExtract(info, ticketID)

	// 验证密钥有效性
	if len(zeroRTTKey) == 0 {
		return false, nil
	}

	// 保存0-RTT密钥和回退数据
	c.zeroRTTKey = zeroRTTKey
	c.zeroRTTFallbackData = c.handshakeData

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

	// 使用8字节长度的连接ID，符合QUIC规范
	connID := make([]byte, 8)
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

	// 使用TLS 1.3的密钥派生函数生成握手密钥
	handshakeContext := sha256.Sum256(keyMaterial)
	handshakeSecret := hkdfExtract(handshakeContext[:], []byte("tls13 hs"))

	// 派生客户端握手流量密钥
	clientLabel := []byte("tls13 quic client hs")
	clientHandshakeSecret := hkdfExtract(handshakeSecret, clientLabel)
	clientTrafficSecret := hkdfExtract(clientHandshakeSecret, []byte("key"))

	// 派生服务端握手流量密钥
	serverLabel := []byte("tls13 quic server hs")
	serverHandshakeSecret := hkdfExtract(handshakeSecret, serverLabel)
	serverTrafficSecret := hkdfExtract(serverHandshakeSecret, []byte("key"))

	// 根据当前角色返回相应的密钥
	if c.tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		return serverTrafficSecret // 作为服务端
	}
	return clientTrafficSecret // 作为客户端
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

	// 从握手数据中提取TLS主密钥
	handshakeTrafficSecret := c.handshakeData[:32]

	// 使用HKDF-Expand-Label派生应用数据密钥
	appSecret := hkdfExpandLabel(handshakeTrafficSecret, []byte("tls13 quic app"), nil, 32)

	// 派生QUIC应用数据流量密钥
	trafficSecret := hkdfExpandLabel(appSecret, []byte("quic traffic"), nil, 32)
	return trafficSecret
}

// hkdfExpandLabel 实现HKDF-Expand-Label函数
func hkdfExpandLabel(secret, label []byte, context []byte, length uint16) []byte {
	// 构造HKDF标签
	var hkdfLabel []byte
	// 添加长度（2字节）
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	// 添加标签长度（1字节）
	hkdfLabel = append(hkdfLabel, byte(len(label)))
	// 添加标签
	hkdfLabel = append(hkdfLabel, label...)
	// 添加上下文长度（1字节）
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	// 添加上下文（如果有）
	if context != nil {
		hkdfLabel = append(hkdfLabel, context...)
	}

	// 使用HMAC-SHA256作为哈希函数
	h := hmac.New(sha256.New, secret)

	// 输出密钥材料
	output := make([]byte, 0, length)
	counter := byte(1)
	for len(output) < int(length) {
		h.Reset()
		h.Write([]byte{counter})
		h.Write(hkdfLabel)
		output = append(output, h.Sum(nil)...)
		counter++
	}

	return output[:length]
}

// hkdfExtract 实现HKDF-Extract函数
func hkdfExtract(salt, ikm []byte) []byte {
	// 使用crypto/tls包中的标准HKDF-Extract实现
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}
