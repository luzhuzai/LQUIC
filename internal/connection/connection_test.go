package connection

import (
	"net"
	"testing"

	"LQUIC/internal/crypto"
	"LQUIC/internal/packet"
	"LQUIC/internal/protocol"
)

func TestNewConnection(t *testing.T) {
	// 创建测试数据
	destConnID := protocol.ConnectionID{1, 2, 3, 4}
	srcConnID := protocol.ConnectionID{5, 6, 7, 8}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	cryptoSetup := crypto.NewCryptoSetup(nil)

	// 创建连接
	c := NewConnection(destConnID, srcConnID, remoteAddr, conn, cryptoSetup)

	// 验证初始状态
	if c.GetState() != StateInitial {
		t.Errorf("初始状态错误，期望%v，实际%v", StateInitial, c.GetState())
	}
	if string(c.destConnID) != string(destConnID) {
		t.Error("目标连接ID设置错误")
	}
	if string(c.srcConnID) != string(srcConnID) {
		t.Error("源连接ID设置错误")
	}
	if c.remoteAddr.String() != remoteAddr.String() {
		t.Error("远程地址设置错误")
	}

	// 清理资源
	c.Close()
	conn.Close()
}

func TestConnectionState(t *testing.T) {
	// 创建测试连接
	c := NewConnection(
		protocol.ConnectionID{1, 2, 3, 4},
		protocol.ConnectionID{5, 6, 7, 8},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
		nil,
		crypto.NewCryptoSetup(nil),
	)

	// 测试状态转换
	if c.GetState() != StateInitial {
		t.Error("初始状态错误")
	}

	c.setState(StateHandshaking)
	if c.GetState() != StateHandshaking {
		t.Error("握手状态设置失败")
	}

	c.setState(StateEstablished)
	if c.GetState() != StateEstablished {
		t.Error("已建立状态设置失败")
	}

	// 测试关闭
	c.Close()
	if c.GetState() != StateClosed {
		t.Error("关闭状态设置失败")
	}
}

func TestPacketNumberGeneration(t *testing.T) {
	// 创建测试连接
	c := NewConnection(
		protocol.ConnectionID{1, 2, 3, 4},
		protocol.ConnectionID{5, 6, 7, 8},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
		nil,
		crypto.NewCryptoSetup(nil),
	)

	// 测试包序号生成
	pn1 := c.generatePacketNumber()
	pn2 := c.generatePacketNumber()

	if pn1 >= pn2 {
		t.Error("包序号应该递增")
	}

	// 测试包序号验证
	if !c.validatePacketNumber(pn2 + 1) {
		t.Error("有效的包序号验证失败")
	}

	if c.validatePacketNumber(pn1) {
		t.Error("过期的包序号验证应该失败")
	}
}

func TestHandlePacket(t *testing.T) {
	// 创建测试连接
	c := NewConnection(
		protocol.ConnectionID{1, 2, 3, 4},
		protocol.ConnectionID{5, 6, 7, 8},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
		nil,
		crypto.NewCryptoSetup(nil),
	)

	// 测试处理Initial包
	initialPacket := &packet.Packet{
		Header: packet.Header{
			Type:         protocol.PacketTypeInitial,
			Version:      protocol.Version,
			DestConnID:   protocol.ConnectionID{1, 2, 3, 4},
			PacketNumber: c.generatePacketNumber() + 1,
		},
		Payload: []byte("initial payload"),
	}

	err := c.HandlePacket(initialPacket)
	if err != nil {
		t.Errorf("处理Initial包失败: %v", err)
	}
	if c.GetState() != StateHandshaking {
		t.Error("处理Initial包后状态应该是握手中")
	}

	// 测试处理无效的包序号
	invalidPacket := &packet.Packet{
		Header: packet.Header{
			Type:         protocol.PacketTypeInitial,
			PacketNumber: 0, // 无效的包序号
		},
	}

	err = c.HandlePacket(invalidPacket)
	if err == nil {
		t.Error("处理无效包序号应该返回错误")
	}

	// 清理资源
	c.Close()
}
