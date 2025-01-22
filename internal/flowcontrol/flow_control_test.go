package flowcontrol

import (
	"testing"

	"LQUIC/internal/protocol"
)

func TestNewFlowController(t *testing.T) {
	// 创建流量控制器
	initialSize := WindowSize(1024)
	maxSize := WindowSize(4096)
	fc := NewFlowController(initialSize, maxSize)

	// 验证初始状态
	if fc.windowSize != initialSize {
		t.Errorf("初始窗口大小错误，期望%d，实际%d", initialSize, fc.windowSize)
	}
	if fc.maxWindowSize != maxSize {
		t.Errorf("最大窗口大小错误，期望%d，实际%d", maxSize, fc.maxWindowSize)
	}
	if fc.bytesInFlight != 0 {
		t.Error("初始已发送但未确认的字节数应为0")
	}
	if fc.recvWindowSize != initialSize {
		t.Errorf("初始接收窗口大小错误，期望%d，实际%d", initialSize, fc.recvWindowSize)
	}
}

func TestCanSend(t *testing.T) {
	// 创建流量控制器
	fc := NewFlowController(1024, 4096)

	// 测试可以发送的情况
	if !fc.CanSend(100) {
		t.Error("应该允许发送100字节")
	}

	// 测试超出窗口大小的情况
	if fc.CanSend(2000) {
		t.Error("不应该允许发送超出窗口大小的数据")
	}

	// 发送一些数据后测试
	fc.OnDataSent(500)
	if !fc.CanSend(100) {
		t.Error("发送500字节后应该还能发送100字节")
	}
	if fc.CanSend(600) {
		t.Error("发送500字节后不应该允许发送600字节")
	}

	// 验证bytesInFlight的值
	if fc.GetBytesInFlight() != 500 {
		t.Errorf("已发送但未确认的字节数错误，期望500，实际%d", fc.GetBytesInFlight())
	}
}

func TestOnDataSent(t *testing.T) {
	// 创建流量控制器
	fc := NewFlowController(1024, 4096)

	// 测试发送数据
	fc.OnDataSent(100)
	if fc.GetBytesInFlight() != 100 {
		t.Errorf("已发送但未确认的字节数错误，期望100，实际%d", fc.GetBytesInFlight())
	}

	// 测试多次发送
	fc.OnDataSent(200)
	if fc.GetBytesInFlight() != 300 {
		t.Errorf("累计发送但未确认的字节数错误，期望300，实际%d", fc.GetBytesInFlight())
	}
}

func TestUpdateWindow(t *testing.T) {
	// 创建流量控制器
	fc := NewFlowController(1024, 4096)

	// 先发送一些数据
	fc.OnDataSent(500)
	initialBytesInFlight := fc.GetBytesInFlight()

	// 更新窗口
	fc.UpdateWindow(protocol.ByteCount(200))
	if fc.GetBytesInFlight() != initialBytesInFlight-200 {
		t.Errorf("更新窗口后，已发送但未确认的字节数错误，期望%d，实际%d", initialBytesInFlight-200, fc.GetBytesInFlight())
	}

	// 再次更新窗口
	fc.UpdateWindow(protocol.ByteCount(300))
	if fc.GetBytesInFlight() != 0 {
		t.Errorf("所有数据都已确认，bytesInFlight应为0，实际为%d", fc.GetBytesInFlight())
	}
}

func TestGetWindowSize(t *testing.T) {
	// 创建流量控制器
	fc := NewFlowController(1024, 4096)

	// 测试初始窗口大小
	if fc.GetWindowSize() != 1024 {
		t.Errorf("初始窗口大小错误，期望1024，实际%d", fc.GetWindowSize())
	}

	// 发送数据后测试
	fc.OnDataSent(500)
	if fc.GetWindowSize() != 1024 { // 窗口大小不会因为发送数据而改变
		t.Errorf("发送数据后窗口大小错误，期望1024，实际%d", fc.GetWindowSize())
	}

	// 更新窗口后测试
	fc.UpdateWindow(protocol.ByteCount(200))
	if fc.GetWindowSize() != 1024 { // 窗口大小保持不变
		t.Errorf("更新窗口后大小错误，期望1024，实际%d", fc.GetWindowSize())
	}
}
