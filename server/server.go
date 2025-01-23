// Package server 实现QUIC服务器功能
package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"LQUIC/internal/connection"
	"LQUIC/internal/crypto"
	"LQUIC/internal/packet"
	"LQUIC/internal/protocol"
)

// Config 服务器配置
type Config struct {
	Addr      string
	TLSConfig *tls.Config
	// 最大并发连接数
	MaxConnections int
}

// Server QUIC服务器
type Server struct {
	config Config
	conn   *net.UDPConn
	// 连接管理
	connections    map[string]*connection.Connection
	connectionsMux sync.RWMutex
	// 连接ID生成器
	idGenerator *connection.IDGenerator
	// 关闭通道
	closeChan chan struct{}
}

// New 创建新的QUIC服务器
func New(config Config) (*Server, error) {
	if config.MaxConnections <= 0 {
		config.MaxConnections = 1000 // 默认最大连接数
	}

	return &Server{
		config:      config,
		connections: make(map[string]*connection.Connection),
		idGenerator: connection.NewIDGenerator(connection.IDLength),
		closeChan:   make(chan struct{}),
	}, nil
}

// Start 启动服务器
func (s *Server) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.config.Addr)
	if err != nil {
		return fmt.Errorf("解析地址失败: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("监听UDP失败: %v", err)
	}
	s.conn = conn

	go s.acceptLoop()
	return nil
}

// acceptLoop 接受新连接
func (s *Server) acceptLoop() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-s.closeChan:
			return
		default:
			n, remoteAddr, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			go s.handlePacket(buf[:n], remoteAddr)
		}
	}
}

// handlePacket 处理接收到的数据包
func (s *Server) handlePacket(data []byte, remoteAddr *net.UDPAddr) {
	// 解析数据包
	p, err := packet.Unpack(data)
	if err != nil {
		return
	}

	// 获取或创建连接
	connKey := string(p.Header.DestConnID)
	s.connectionsMux.RLock()
	conn, exists := s.connections[connKey]
	s.connectionsMux.RUnlock()

	// 如果是新连接且是Initial包
	if !exists && p.Header.Type == protocol.PacketTypeInitial {
		// 创建新的加密设置
		cryptoSetup := crypto.NewCryptoSetup(s.config.TLSConfig)

		// 生成服务器连接ID
		srcConnID, err := s.idGenerator.GenerateConnectionID()
		if err != nil {
			return
		}

		// 创建新连接
		conn = connection.NewConnection(
			p.Header.DestConnID,
			srcConnID,
			remoteAddr,
			s.conn,
			cryptoSetup,
		)

		// 存储连接
		s.connectionsMux.Lock()
		if len(s.connections) >= s.config.MaxConnections {
			s.connectionsMux.Unlock()
			return
		}
		s.connections[connKey] = conn
		s.connectionsMux.Unlock()
	}

	// 如果找不到连接
	if conn == nil {
		return
	}

	// 处理数据包
	conn.HandlePacket(p)
}

// Close 关闭服务器
func (s *Server) Close() error {
	close(s.closeChan)
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
