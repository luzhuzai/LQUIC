# LQUIC - 轻量级QUIC协议实现

## 项目概述

LQUIC是一个轻量级的QUIC协议实现，QUIC是一个基于UDP的传输层协议，提供了类似TCP的可靠性保证，同时具有更低的延迟和更好的多路复用能力。

### 主要特性

- 基于UDP的可靠传输
- 内置TLS 1.3加密
- 连接多路复用
- 流量控制
- 零RTT连接建立

## 架构设计

### 模块划分

项目采用模块化设计，主要包含以下核心模块：

- **packet**: 负责QUIC数据包的封装和解析
  - 支持各类QUIC数据包类型（Initial、Handshake、OneRTT等）
  - 提供数据包的序列化和反序列化功能

- **connection**: 管理QUIC连接
  - 处理连接建立和断开
  - 维护连接状态
  - 管理数据包的收发

- **crypto**: 实现加密相关功能
  - 集成TLS 1.3
  - 处理加密握手
  - 保护数据安全

- **flowcontrol**: 实现流量控制
  - 防止发送方超载接收方
  - 优化网络资源使用

- **protocol**: 定义协议常量和类型
  - 包含协议版本信息
  - 定义数据包类型
  - 声明公共接口

- **server/client**: 服务端和客户端实现
  - 提供面向用户的API
  - 处理网络事件

### 数据流

1. 数据包处理流程：
   ```
   应用层数据 -> 分片 -> 加密 -> 打包 -> 发送
   接收 -> 解包 -> 解密 -> 重组 -> 应用层数据
   ```

2. 连接建立流程：
   ```
   客户端 Initial包 -> 服务端
   服务端 Initial包 -> 客户端
   完成加密握手
   建立QUIC连接
   ```

## 核心功能实现

### 数据包处理

数据包模块(`packet`)实现了QUIC数据包的基本操作：

```go
// 数据包结构
type Packet struct {
    Header  Header
    Payload []byte
}

// 数据包头部
type Header struct {
    Type         protocol.PacketType
    Version      uint32
    DestConnID   protocol.ConnectionID
    SrcConnID    protocol.ConnectionID
    PacketNumber protocol.PacketNumber
}
```

### 连接管理

连接模块(`connection`)负责维护QUIC连接的生命周期：

- 连接建立：处理Initial包和Handshake包
- 数据传输：管理OneRTT包的收发
- 连接关闭：处理连接终止和资源清理

### 加密实现

加密模块(`crypto`)集成了TLS 1.3，提供：

- 安全的密钥协商
- 数据包的加密和认证
- 密钥更新机制

### 流量控制

流量控制模块(`flowcontrol`)实现了：

- 基于窗口的流量控制
- 拥塞控制
- 流级别和连接级别的控制

## API使用指南

### 服务端示例

```go
// 创建服务器
server, err := server.New(server.Config{
    Addr:      ":4242",
    TLSConfig: tlsConfig,
})
if err != nil {
    log.Fatal(err)
}

// 启动服务器
err = server.Start()
if err != nil {
    log.Fatal(err)
}
```

### 客户端示例

```go
// 创建客户端连接
conn, err := client.Connect("localhost:4242", &tls.Config{
    // TLS配置
})
if err != nil {
    log.Fatal(err)
}
defer conn.Close()
```

## 测试

项目包含完整的单元测试和集成测试：

```bash
# 运行所有测试
go test ./...

# 运行特定模块测试
go test ./internal/packet
go test ./internal/connection
```

### 测试覆盖

主要测试场景包括：

- 数据包的序列化和反序列化
- 连接建立和断开
- 加密握手过程
- 流量控制机制
- 错误处理和恢复

## 贡献指南

欢迎提交Issue和Pull Request。在提交代码前，请确保：

1. 代码符合Go的代码规范
2. 添加了适当的测试用例
3. 所有测试都能通过
4. 更新了相关文档