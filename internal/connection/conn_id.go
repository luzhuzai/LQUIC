// Package connection 实现QUIC连接管理相关功能
package connection

import (
	"crypto/rand"
	"fmt"

	"LQUIC/internal/protocol"
)

// IDLength 定义连接ID的默认长度
const IDLength = 8

// IDGenerator 用于生成连接ID
type IDGenerator struct {
	length int
}

// NewIDGenerator 创建一个新的连接ID生成器
func NewIDGenerator(length int) *IDGenerator {
	return &IDGenerator{length: length}
}

// GenerateConnectionID 生成一个新的连接ID
func (g *IDGenerator) GenerateConnectionID() (protocol.ConnectionID, error) {
	id := make([]byte, g.length)
	_, err := rand.Read(id)
	if err != nil {
		return nil, fmt.Errorf("生成连接ID失败: %v", err)
	}
	return protocol.ConnectionID(id), nil
}

// IDManager 管理连接ID的生命周期
type IDManager struct {
	activeIDs    map[string]protocol.ConnectionID
	generator    *IDGenerator
	maxActiveIDs int
}

// NewIDManager 创建一个新的连接ID管理器
func NewIDManager(generator *IDGenerator, maxActiveIDs int) *IDManager {
	return &IDManager{
		activeIDs:    make(map[string]protocol.ConnectionID),
		generator:    generator,
		maxActiveIDs: maxActiveIDs,
	}
}

// AddConnectionID 添加一个新的连接ID
func (m *IDManager) AddConnectionID(id protocol.ConnectionID) error {
	if len(m.activeIDs) >= m.maxActiveIDs {
		return fmt.Errorf("已达到最大活跃连接ID数量")
	}
	m.activeIDs[string(id)] = id
	return nil
}

// RemoveConnectionID 移除一个连接ID
func (m *IDManager) RemoveConnectionID(id protocol.ConnectionID) {
	delete(m.activeIDs, string(id))
}

// GetActiveIDs 获取所有活跃的连接ID
func (m *IDManager) GetActiveIDs() []protocol.ConnectionID {
	ids := make([]protocol.ConnectionID, 0, len(m.activeIDs))
	for _, id := range m.activeIDs {
		ids = append(ids, id)
	}
	return ids
}
