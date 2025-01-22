# Connection 模块

## 概述

Connection模块是LQUIC的核心组件之一，负责管理QUIC连接的生命周期，包括连接的建立、维护和终止。该模块实现了QUIC协议的连接管理功能，确保数据传输的可靠性和安全性。

## 主要组件

### Connection（连接对象）

```go
type Connection struct {
    DestConnID protocol.ConnectionID  // 目标连接ID
    SrcConnID  protocol.ConnectionID  // 源连接ID
    RemoteAddr *net.UDPAddr          // 远程地址
    State      ConnectionState        // 连接状态
    // ... 其他字段
}
```

### ConnectionState（连接状态）

连接状态包括：
- Initial：初始状态
- Handshaking：握手中
- Connected：已连接
- Closing：关闭中
- Closed：已关闭

## 核心功能

### 1. 连接建立

- **NewConnection()**: 创建新的连接对象
- **handleInitialPacket()**: 处理Initial包，启动握手过程
- **handleHandshakePacket()**: 处理Handshake包，完成握手

连接建立过程：
1. 接收Initial包
2. 验证连接参数
3. 启动TLS握手
4. 交换Handshake包
5. 建立加密通道

### 2. 数据传输

- **handleOneRTTPacket()**: 处理OneRTT数据包
- **validatePacketNumber()**: 验证数据包序号
- **processReceivedPacket()**: 处理接收到的数据包

数据传输功能：
1. 包序号验证和处理
2. 流量控制
3. 拥塞控制
4. 丢包重传

### 3. 连接管理

- **Close()**: 关闭连接
- **updateState()**: 更新连接状态
- **handleTimeout()**: 处理超时事件

## 错误处理

模块实现了完善的错误处理机制：

- 连接超时处理
- 握手失败处理
- 包序号验证失败处理
- 状态转换错误处理

## 使用示例

### 创建和管理连接

```go
// 创建连接
conn := NewConnection(
    protocol.ConnectionID{1, 2, 3, 4},
    protocol.ConnectionID{5, 6, 7, 8},
    remoteAddr,
    cryptoSetup,
)

// 处理接收到的数据包
err := conn.HandlePacket(packet)
if err != nil {
    // 处理错误
}

// 关闭连接
conn.Close()
```

### 处理不同类型的数据包

```go
func (c *Connection) HandlePacket(p *packet.Packet) error {
    switch p.Header.Type {
    case protocol.PacketTypeInitial:
        return c.handleInitialPacket(p)
    case protocol.PacketTypeHandshake:
        return c.handleHandshakePacket(p)
    case protocol.PacketTypeOneRTT:
        return c.handleOneRTTPacket(p)
    default:
        return fmt.Errorf("未知的包类型")
    }
}
```

## 测试

模块包含完整的单元测试，覆盖以下场景：

1. 连接建立和关闭
2. 数据包处理
3. 状态转换
4. 错误处理
5. 超时处理

运行测试：
```bash
go test ./internal/connection
```