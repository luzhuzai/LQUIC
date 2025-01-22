package server

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"LQUIC/internal/packet"
	"LQUIC/internal/protocol"
)

func TestNewServer(t *testing.T) {
	// 创建服务器配置
	config := Config{
		Addr:           ":12345",
		TLSConfig:      &tls.Config{},
		MaxConnections: 100,
	}

	// 创建服务器
	server, err := New(config)
	if err != nil {
		t.Fatalf("创建服务器失败: %v", err)
	}

	// 验证服务器初始化
	if server.config.Addr != config.Addr {
		t.Errorf("地址配置错误，期望 %s，实际 %s", config.Addr, server.config.Addr)
	}
	if server.config.MaxConnections != config.MaxConnections {
		t.Errorf("最大连接数配置错误，期望 %d，实际 %d", config.MaxConnections, server.config.MaxConnections)
	}
	if server.idGenerator == nil {
		t.Error("连接ID生成器未初始化")
	}
	if server.connections == nil {
		t.Error("连接管理映射未初始化")
	}
}

func TestStartServer(t *testing.T) {
	// 创建服务器
	server, err := New(Config{
		Addr:      ":0", // 使用随机端口
		TLSConfig: &tls.Config{},
	})
	if err != nil {
		t.Fatalf("创建服务器失败: %v", err)
	}

	// 启动服务器
	err = server.Start()
	if err != nil {
		t.Fatalf("启动服务器失败: %v", err)
	}
	defer server.Close()

	// 等待服务器启动
	time.Sleep(100 * time.Millisecond)

	// 验证服务器状态
	if server.conn == nil {
		t.Error("UDP连接未建立")
	}
}

func TestHandlePacket(t *testing.T) {
	// 创建服务器
	server, err := New(Config{
		Addr:      ":0",
		TLSConfig: &tls.Config{},
	})
	if err != nil {
		t.Fatalf("创建服务器失败: %v", err)
	}

	// 启动服务器
	err = server.Start()
	if err != nil {
		t.Fatalf("启动服务器失败: %v", err)
	}
	defer server.Close()

	// 创建客户端连接
	clientConn, err := net.DialUDP("udp", nil, server.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("创建客户端连接失败: %v", err)
	}
	defer clientConn.Close()

	// 创建并发送初始包
	destConnID := []byte{1, 2, 3, 4}
	p := &packet.Packet{
		Header: packet.Header{
			Type:       protocol.PacketTypeInitial,
			Version:    protocol.Version,
			DestConnID: destConnID,
		},
		Payload: []byte("test payload"),
	}

	// 序列化并发送数据包
	data, err := p.Pack()
	if err != nil {
		t.Fatalf("数据包序列化失败: %v", err)
	}
	_, err = clientConn.Write(data)
	if err != nil {
		t.Fatalf("发送数据包失败: %v", err)
	}

	// 等待服务器处理
	time.Sleep(100 * time.Millisecond)

	// 验证连接是否建立
	server.connectionsMux.RLock()
	conn, exists := server.connections[string(destConnID)]
	server.connectionsMux.RUnlock()

	if !exists {
		t.Error("服务器未创建连接")
	}
	if conn == nil {
		t.Error("连接对象为空")
	}
}

func TestMaxConnections(t *testing.T) {
	// 创建服务器，设置最大连接数为1
	server, err := New(Config{
		Addr:           ":0",
		TLSConfig:      &tls.Config{},
		MaxConnections: 1,
	})
	if err != nil {
		t.Fatalf("创建服务器失败: %v", err)
	}

	// 启动服务器
	err = server.Start()
	if err != nil {
		t.Fatalf("启动服务器失败: %v", err)
	}
	defer server.Close()

	// 创建两个客户端连接
	clientConn1, err := net.DialUDP("udp", nil, server.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("创建第一个客户端连接失败: %v", err)
	}
	defer clientConn1.Close()

	clientConn2, err := net.DialUDP("udp", nil, server.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("创建第二个客户端连接失败: %v", err)
	}
	defer clientConn2.Close()

	// 发送第一个连接的初始包
	destConnID1 := []byte{1, 2, 3, 4}
	p1 := &packet.Packet{
		Header: packet.Header{
			Type:       protocol.PacketTypeInitial,
			Version:    protocol.Version,
			DestConnID: destConnID1,
		},
		Payload: []byte("test payload 1"),
	}
	data1, _ := p1.Pack()
	_, err = clientConn1.Write(data1)
	if err != nil {
		t.Fatalf("发送第一个数据包失败: %v", err)
	}

	// 等待第一个连接建立
	time.Sleep(100 * time.Millisecond)

	// 发送第二个连接的初始包
	destConnID2 := []byte{5, 6, 7, 8}
	p2 := &packet.Packet{
		Header: packet.Header{
			Type:       protocol.PacketTypeInitial,
			Version:    protocol.Version,
			DestConnID: destConnID2,
		},
		Payload: []byte("test payload 2"),
	}
	data2, _ := p2.Pack()
	_, err = clientConn2.Write(data2)
	if err != nil {
		t.Fatalf("发送第二个数据包失败: %v", err)
	}

	// 等待处理
	time.Sleep(100 * time.Millisecond)

	// 验证连接数量
	server.connectionsMux.RLock()
	connCount := len(server.connections)
	server.connectionsMux.RUnlock()

	if connCount > 1 {
		t.Errorf("超出最大连接数限制，当前连接数: %d", connCount)
	}
}
