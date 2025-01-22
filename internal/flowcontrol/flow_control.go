// Package flowcontrol 实现QUIC的流量控制和拥塞控制
package flowcontrol

import (
	"sync"
	"time"

	"LQUIC/internal/protocol"
)

// WindowSize 定义流量控制窗口大小
type WindowSize uint64

// FlowController 流量控制器
type FlowController struct {
	mutex sync.Mutex

	// 当前可用窗口大小
	windowSize WindowSize
	// 已发送但未确认的字节数
	bytesInFlight protocol.ByteCount
	// 最大窗口大小
	maxWindowSize WindowSize
	// 接收窗口大小
	recvWindowSize WindowSize
	// 最后一次窗口更新时间
	lastWindowUpdate time.Time
}

// NewFlowController 创建新的流量控制器
func NewFlowController(initialWindowSize, maxWindowSize WindowSize) *FlowController {
	return &FlowController{
		windowSize:     initialWindowSize,
		maxWindowSize:  maxWindowSize,
		recvWindowSize: initialWindowSize,
	}
}

// UpdateWindow 更新发送窗口
func (f *FlowController) UpdateWindow(bytes protocol.ByteCount) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.bytesInFlight -= bytes
	f.lastWindowUpdate = time.Now()
}

// UpdateRecvWindow 更新接收窗口
func (f *FlowController) UpdateRecvWindow(bytes protocol.ByteCount) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.recvWindowSize += WindowSize(bytes)
	if f.recvWindowSize > f.maxWindowSize {
		f.recvWindowSize = f.maxWindowSize
	}
}

// CanSend 检查是否可以发送指定大小的数据
func (f *FlowController) CanSend(bytes protocol.ByteCount) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	return f.bytesInFlight+bytes <= protocol.ByteCount(f.windowSize)
}

// OnDataSent 记录已发送的数据
func (f *FlowController) OnDataSent(bytes protocol.ByteCount) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.bytesInFlight += bytes
}

// GetWindowSize 获取当前窗口大小
func (f *FlowController) GetWindowSize() WindowSize {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	return f.windowSize
}

// GetBytesInFlight 获取已发送但未确认的字节数
func (f *FlowController) GetBytesInFlight() protocol.ByteCount {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	return f.bytesInFlight
}
