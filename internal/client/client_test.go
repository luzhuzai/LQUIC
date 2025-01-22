package client

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"LQUIC/internal/packet"
	"LQUIC/internal/protocol"
)

func TestNewClient(t *testing.T) {
	// 创建客户端配置
	config := Config{
		RemoteAddr: "localhost:12345",
		TLSConfig:  &tls.Config{},
	}

	// 创建客户端
	client, err := New(config)
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}

	// 验证客户端初始化
	if client.config.RemoteAddr != config.RemoteAddr {
		t.Errorf("远程地址配置错误，期望 %s，实际 %s", config.RemoteAddr, client.config.RemoteAddr)
	}
	if client.cryptoSetup == nil {
		t.Error("加密设置未初始化")
	}
	if client.idGenerator == nil {
		t.Error("连接ID生成器未初始化")
	}
}

func TestConnect(t *testing.T) {
	// 创建模拟服务器
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("创建模拟服务器失败: %v", err)
	}
	defer listener.Close()

	// 获取服务器地址
	serverAddr := listener.LocalAddr().String()

	// 创建客户端
	client, err := New(Config{
		RemoteAddr: serverAddr,
		TLSConfig:  &tls.Config{},
	})
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}

	// 启动服务器监听协程
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := listener.ReadFromUDP(buf)
		if err != nil {
			return
		}

		// 解析收到的数据包
		p, err := packet.Unpack(buf[:n])
		if err != nil {
			return
		}

		// 验证收到的初始包
		if p.Header.Type != protocol.PacketTypeInitial {
			t.Errorf("收到的不是初始包，实际类型: %v", p.Header.Type)
		}

		// 发送模拟响应
		resp := &packet.Packet{
			Header: packet.Header{
				Type:       protocol.PacketTypeInitial,
				Version:    protocol.Version,
				SrcConnID:  p.Header.DestConnID,
				DestConnID: p.Header.SrcConnID,
			},
			Payload: []byte("test response"),
		}
		data, err := resp.Pack()
		if err != nil {
			return
		}
		listener.WriteToUDP(data, addr)
	}()

	// 测试连接
	err = client.Connect()
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer client.Close()

	// 等待连接建立
	time.Sleep(100 * time.Millisecond)

	// 验证连接状态
	if client.conn == nil {
		t.Error("UDP连接未建立")
	}
}

func TestHandlePacket(t *testing.T) {
	// 创建模拟服务器
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("创建模拟服务器失败: %v", err)
	}
	defer listener.Close()

	// 获取服务器地址
	serverAddr := listener.LocalAddr().String()

	// 创建客户端
	client, err := New(Config{
		RemoteAddr: serverAddr,
		TLSConfig:  &tls.Config{},
	})
	if err != nil {
		t.Fatalf("创建客户端失败: %v", err)
	}

	// 初始化客户端连接
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		t.Fatalf("解析地址失败: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("连接服务器失败: %v", err)
	}
	client.conn = conn
	defer client.Close()

	// 创建测试数据包
	srcConnID := []byte{1, 2, 3, 4}
	destConnID := []byte{5, 6, 7, 8}
	p := &packet.Packet{
		Header: packet.Header{
			Type:         protocol.PacketTypeInitial,
			Version:      protocol.Version,
			SrcConnID:    srcConnID,
			DestConnID:   destConnID,
			PacketNumber: 0,
		},
		Payload: []byte("test payload"),
	}

	// 序列化数据包
	data, err := p.Pack()
	if err != nil {
		t.Fatalf("数据包序列化失败: %v", err)
	}

	// 测试数据包处理
	client.handlePacket(data)

	// 验证连接是否正确创建
	client.connectionMux.RLock()
	defer client.connectionMux.RUnlock()

	if client.connection == nil {
		t.Error("连接未创建")
	} else {
		if string(client.connection.GetDestConnID()) != string(destConnID) {
			t.Error("目标连接ID不匹配")
		}
		if string(client.connection.GetSrcConnID()) != string(srcConnID) {
			t.Error("源连接ID不匹配")
		}
	}
}
