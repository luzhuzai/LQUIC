// Package crypto 实现QUIC的加密和安全功能
package crypto

import (
	"crypto/rand"
	"sync"
	"time"
)

// SessionTicket 表示会话票据
type SessionTicket struct {
	// 票据ID
	ID []byte
	// 会话密钥
	SessionKey []byte
	// 创建时间
	CreatedAt time.Time
	// 过期时间
	ExpiresAt time.Time
}

// SessionManager 管理会话票据和恢复
type SessionManager struct {
	mutex sync.RWMutex
	// 存储会话票据，key为票据ID
	tickets map[string]*SessionTicket
	// 会话票据有效期
	ticketValidity time.Duration
}

// NewSessionManager 创建新的会话管理器
func NewSessionManager() *SessionManager {
	return &SessionManager{
		tickets:        make(map[string]*SessionTicket),
		ticketValidity: 24 * time.Hour, // 默认票据有效期为24小时
	}
}

// CreateTicket 创建新的会话票据
func (sm *SessionManager) CreateTicket() (*SessionTicket, error) {
	// 生成随机票据ID
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}

	// 生成会话密钥
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	now := time.Now()
	ticket := &SessionTicket{
		ID:         id,
		SessionKey: key,
		CreatedAt:  now,
		ExpiresAt:  now.Add(sm.ticketValidity),
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.tickets[string(id)] = ticket

	return ticket, nil
}

// GetTicket 获取会话票据
func (sm *SessionManager) GetTicket(id []byte) *SessionTicket {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	ticket, exists := sm.tickets[string(id)]
	if !exists || time.Now().After(ticket.ExpiresAt) {
		return nil
	}

	return ticket
}

// RemoveExpiredTickets 清理过期的会话票据
func (sm *SessionManager) RemoveExpiredTickets() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()
	for id, ticket := range sm.tickets {
		if now.After(ticket.ExpiresAt) {
			delete(sm.tickets, id)
		}
	}
}
