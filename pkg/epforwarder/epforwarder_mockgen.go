// Code generated by MockGen. DO NOT EDIT.
// Source: epforwarder.go

// Package epforwarder is a generated GoMock package.
package epforwarder

import (
	message "github.com/DataDog/datadog-agent/pkg/logs/message"
	gomock "github.com/golang/mock/gomock"
)

// MockEventPlatformForwarder is a mock of EventPlatformForwarder interface.
type MockEventPlatformForwarder struct {
	ctrl     *gomock.Controller
	recorder *MockEventPlatformForwarderMockRecorder
}

// MockEventPlatformForwarderMockRecorder is the mock recorder for MockEventPlatformForwarder.
type MockEventPlatformForwarderMockRecorder struct {
	mock *MockEventPlatformForwarder
}

// NewMockEventPlatformForwarder creates a new mock instance.
func NewMockEventPlatformForwarder(ctrl *gomock.Controller) *MockEventPlatformForwarder {
	panic("not called")
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEventPlatformForwarder) EXPECT() *MockEventPlatformForwarderMockRecorder {
	panic("not called")
}

// Purge mocks base method.
func (m *MockEventPlatformForwarder) Purge() map[string][]*message.Message {
	panic("not called")
}

// Purge indicates an expected call of Purge.
func (mr *MockEventPlatformForwarderMockRecorder) Purge() *gomock.Call {
	panic("not called")
}

// SendEventPlatformEvent mocks base method.
func (m *MockEventPlatformForwarder) SendEventPlatformEvent(e *message.Message, eventType string) error {
	panic("not called")
}

// SendEventPlatformEvent indicates an expected call of SendEventPlatformEvent.
func (mr *MockEventPlatformForwarderMockRecorder) SendEventPlatformEvent(e, eventType interface{}) *gomock.Call {
	panic("not called")
}

// SendEventPlatformEventBlocking mocks base method.
func (m *MockEventPlatformForwarder) SendEventPlatformEventBlocking(e *message.Message, eventType string) error {
	panic("not called")
}

// SendEventPlatformEventBlocking indicates an expected call of SendEventPlatformEventBlocking.
func (mr *MockEventPlatformForwarderMockRecorder) SendEventPlatformEventBlocking(e, eventType interface{}) *gomock.Call {
	panic("not called")
}

// Start mocks base method.
func (m *MockEventPlatformForwarder) Start() {
	panic("not called")
}

// Start indicates an expected call of Start.
func (mr *MockEventPlatformForwarderMockRecorder) Start() *gomock.Call {
	panic("not called")
}

// Stop mocks base method.
func (m *MockEventPlatformForwarder) Stop() {
	panic("not called")
}

// Stop indicates an expected call of Stop.
func (mr *MockEventPlatformForwarderMockRecorder) Stop() *gomock.Call {
	panic("not called")
}
