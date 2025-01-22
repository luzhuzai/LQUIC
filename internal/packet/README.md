# Packet 模块

## 概述

Packet模块是LQUIC的核心组件之一，负责QUIC数据包的封装和解析。该模块实现了QUIC协议中各类数据包的序列化和反序列化功能，确保数据在网络传输过程中的完整性和正确性。

## 主要组件

### Header（数据包头部）

```go
type Header struct {
    Type         protocol.PacketType    // 数据包类型
    Version      uint32                 // 协议版本
    DestConnID   protocol.ConnectionID  // 目标连接ID
    SrcConnID    protocol.ConnectionID  // 源连接ID
    PacketNumber protocol.PacketNumber  // 数据包序号
    PayloadLen   protocol.ByteCount     // 负载长度
}
```

### Packet（完整数据包）

```go
type Packet struct {
    Header  Header  // 数据包头部
    Payload []byte  // 数据包负载
}
```

## 核心功能

### 1. 数据包序列化 (Pack)

- **Header.Pack()**: 将数据包头部序列化为字节流
- **Packet.Pack()**: 将完整数据包序列化为字节流

序列化过程包括：
1. 验证包类型的有效性
2. 写入包类型和版本号
3. 写入源和目标连接ID
4. 写入包序号
5. 写入负载长度和负载数据

### 2. 数据包反序列化 (Unpack)

- **Header.Unpack()**: 从字节流解析数据包头部
- **Packet.Unpack()**: 从字节流解析完整数据包

反序列化过程包括：
1. 验证数据包长度
2. 解析包类型和版本号
3. 解析源和目标连接ID
4. 解析包序号
5. 解析负载长度和负载数据

## 错误处理

模块实现了完善的错误处理机制：

- 数据包长度验证
- 包类型有效性检查
- 字段截断检测
- 边界条件处理

## 使用示例

### 创建和发送数据包

```go
// 创建数据包
packet := &Packet{
    Header: Header{
        Type:         protocol.PacketTypeInitial,
        Version:      protocol.Version,
        DestConnID:   protocol.ConnectionID{1, 2, 3, 4},
        SrcConnID:    protocol.ConnectionID{5, 6, 7, 8},
        PacketNumber: 1,
    },
    Payload: []byte("test payload"),
}

// 序列化数据包
data, err := packet.Pack()
if err != nil {
    // 处理错误
}

// 发送数据包
// conn.Write(data)
```

### 接收和解析数据包

```go
// 接收数据
// data, err := conn.Read()

// 解析数据包
packet, err := Unpack(data)
if err != nil {
    // 处理错误
}

// 使用数据包
switch packet.Header.Type {
case protocol.PacketTypeInitial:
    // 处理Initial包
case protocol.PacketTypeHandshake:
    // 处理Handshake包
case protocol.PacketTypeOneRTT:
    // 处理OneRTT包
}
```

## 测试

模块包含完整的单元测试，覆盖以下场景：

1. 数据包的序列化和反序列化
2. 各种包类型的处理
3. 错误情况处理
4. 边界条件测试

运行测试：
```bash
go test ./internal/packet
```