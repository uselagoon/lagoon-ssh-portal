// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/gliderlabs/ssh (interfaces: Session,Context)
//
// Generated by this command:
//
//	mockgen -package=sshtoken_test -destination=ssh_mock_test.go -write_generate_directive github.com/gliderlabs/ssh Session,Context
//

// Package sshtoken_test is a generated GoMock package.
package sshtoken_test

import (
	io "io"
	net "net"
	reflect "reflect"
	time "time"

	ssh "github.com/gliderlabs/ssh"
	gomock "go.uber.org/mock/gomock"
)

//go:generate mockgen -package=sshtoken_test -destination=ssh_mock_test.go -write_generate_directive github.com/gliderlabs/ssh Session,Context

// MockSession is a mock of Session interface.
type MockSession struct {
	ctrl     *gomock.Controller
	recorder *MockSessionMockRecorder
}

// MockSessionMockRecorder is the mock recorder for MockSession.
type MockSessionMockRecorder struct {
	mock *MockSession
}

// NewMockSession creates a new mock instance.
func NewMockSession(ctrl *gomock.Controller) *MockSession {
	mock := &MockSession{ctrl: ctrl}
	mock.recorder = &MockSessionMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSession) EXPECT() *MockSessionMockRecorder {
	return m.recorder
}

// Break mocks base method.
func (m *MockSession) Break(arg0 chan<- bool) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Break", arg0)
}

// Break indicates an expected call of Break.
func (mr *MockSessionMockRecorder) Break(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Break", reflect.TypeOf((*MockSession)(nil).Break), arg0)
}

// Close mocks base method.
func (m *MockSession) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockSessionMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockSession)(nil).Close))
}

// CloseWrite mocks base method.
func (m *MockSession) CloseWrite() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloseWrite")
	ret0, _ := ret[0].(error)
	return ret0
}

// CloseWrite indicates an expected call of CloseWrite.
func (mr *MockSessionMockRecorder) CloseWrite() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseWrite", reflect.TypeOf((*MockSession)(nil).CloseWrite))
}

// Command mocks base method.
func (m *MockSession) Command() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Command")
	ret0, _ := ret[0].([]string)
	return ret0
}

// Command indicates an expected call of Command.
func (mr *MockSessionMockRecorder) Command() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Command", reflect.TypeOf((*MockSession)(nil).Command))
}

// Context mocks base method.
func (m *MockSession) Context() ssh.Context {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Context")
	ret0, _ := ret[0].(ssh.Context)
	return ret0
}

// Context indicates an expected call of Context.
func (mr *MockSessionMockRecorder) Context() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Context", reflect.TypeOf((*MockSession)(nil).Context))
}

// Environ mocks base method.
func (m *MockSession) Environ() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Environ")
	ret0, _ := ret[0].([]string)
	return ret0
}

// Environ indicates an expected call of Environ.
func (mr *MockSessionMockRecorder) Environ() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Environ", reflect.TypeOf((*MockSession)(nil).Environ))
}

// Exit mocks base method.
func (m *MockSession) Exit(arg0 int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exit", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Exit indicates an expected call of Exit.
func (mr *MockSessionMockRecorder) Exit(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exit", reflect.TypeOf((*MockSession)(nil).Exit), arg0)
}

// LocalAddr mocks base method.
func (m *MockSession) LocalAddr() net.Addr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LocalAddr")
	ret0, _ := ret[0].(net.Addr)
	return ret0
}

// LocalAddr indicates an expected call of LocalAddr.
func (mr *MockSessionMockRecorder) LocalAddr() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LocalAddr", reflect.TypeOf((*MockSession)(nil).LocalAddr))
}

// Permissions mocks base method.
func (m *MockSession) Permissions() ssh.Permissions {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Permissions")
	ret0, _ := ret[0].(ssh.Permissions)
	return ret0
}

// Permissions indicates an expected call of Permissions.
func (mr *MockSessionMockRecorder) Permissions() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Permissions", reflect.TypeOf((*MockSession)(nil).Permissions))
}

// Pty mocks base method.
func (m *MockSession) Pty() (ssh.Pty, <-chan ssh.Window, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Pty")
	ret0, _ := ret[0].(ssh.Pty)
	ret1, _ := ret[1].(<-chan ssh.Window)
	ret2, _ := ret[2].(bool)
	return ret0, ret1, ret2
}

// Pty indicates an expected call of Pty.
func (mr *MockSessionMockRecorder) Pty() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Pty", reflect.TypeOf((*MockSession)(nil).Pty))
}

// PublicKey mocks base method.
func (m *MockSession) PublicKey() ssh.PublicKey {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublicKey")
	ret0, _ := ret[0].(ssh.PublicKey)
	return ret0
}

// PublicKey indicates an expected call of PublicKey.
func (mr *MockSessionMockRecorder) PublicKey() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublicKey", reflect.TypeOf((*MockSession)(nil).PublicKey))
}

// RawCommand mocks base method.
func (m *MockSession) RawCommand() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RawCommand")
	ret0, _ := ret[0].(string)
	return ret0
}

// RawCommand indicates an expected call of RawCommand.
func (mr *MockSessionMockRecorder) RawCommand() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RawCommand", reflect.TypeOf((*MockSession)(nil).RawCommand))
}

// Read mocks base method.
func (m *MockSession) Read(arg0 []byte) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Read", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Read indicates an expected call of Read.
func (mr *MockSessionMockRecorder) Read(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Read", reflect.TypeOf((*MockSession)(nil).Read), arg0)
}

// RemoteAddr mocks base method.
func (m *MockSession) RemoteAddr() net.Addr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoteAddr")
	ret0, _ := ret[0].(net.Addr)
	return ret0
}

// RemoteAddr indicates an expected call of RemoteAddr.
func (mr *MockSessionMockRecorder) RemoteAddr() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoteAddr", reflect.TypeOf((*MockSession)(nil).RemoteAddr))
}

// SendRequest mocks base method.
func (m *MockSession) SendRequest(arg0 string, arg1 bool, arg2 []byte) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendRequest", arg0, arg1, arg2)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SendRequest indicates an expected call of SendRequest.
func (mr *MockSessionMockRecorder) SendRequest(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendRequest", reflect.TypeOf((*MockSession)(nil).SendRequest), arg0, arg1, arg2)
}

// Signals mocks base method.
func (m *MockSession) Signals(arg0 chan<- ssh.Signal) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Signals", arg0)
}

// Signals indicates an expected call of Signals.
func (mr *MockSessionMockRecorder) Signals(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Signals", reflect.TypeOf((*MockSession)(nil).Signals), arg0)
}

// Stderr mocks base method.
func (m *MockSession) Stderr() io.ReadWriter {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Stderr")
	ret0, _ := ret[0].(io.ReadWriter)
	return ret0
}

// Stderr indicates an expected call of Stderr.
func (mr *MockSessionMockRecorder) Stderr() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stderr", reflect.TypeOf((*MockSession)(nil).Stderr))
}

// Subsystem mocks base method.
func (m *MockSession) Subsystem() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Subsystem")
	ret0, _ := ret[0].(string)
	return ret0
}

// Subsystem indicates an expected call of Subsystem.
func (mr *MockSessionMockRecorder) Subsystem() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subsystem", reflect.TypeOf((*MockSession)(nil).Subsystem))
}

// User mocks base method.
func (m *MockSession) User() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "User")
	ret0, _ := ret[0].(string)
	return ret0
}

// User indicates an expected call of User.
func (mr *MockSessionMockRecorder) User() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "User", reflect.TypeOf((*MockSession)(nil).User))
}

// Write mocks base method.
func (m *MockSession) Write(arg0 []byte) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Write", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Write indicates an expected call of Write.
func (mr *MockSessionMockRecorder) Write(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*MockSession)(nil).Write), arg0)
}

// MockContext is a mock of Context interface.
type MockContext struct {
	ctrl     *gomock.Controller
	recorder *MockContextMockRecorder
}

// MockContextMockRecorder is the mock recorder for MockContext.
type MockContextMockRecorder struct {
	mock *MockContext
}

// NewMockContext creates a new mock instance.
func NewMockContext(ctrl *gomock.Controller) *MockContext {
	mock := &MockContext{ctrl: ctrl}
	mock.recorder = &MockContextMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockContext) EXPECT() *MockContextMockRecorder {
	return m.recorder
}

// ClientVersion mocks base method.
func (m *MockContext) ClientVersion() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClientVersion")
	ret0, _ := ret[0].(string)
	return ret0
}

// ClientVersion indicates an expected call of ClientVersion.
func (mr *MockContextMockRecorder) ClientVersion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClientVersion", reflect.TypeOf((*MockContext)(nil).ClientVersion))
}

// Deadline mocks base method.
func (m *MockContext) Deadline() (time.Time, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Deadline")
	ret0, _ := ret[0].(time.Time)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// Deadline indicates an expected call of Deadline.
func (mr *MockContextMockRecorder) Deadline() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Deadline", reflect.TypeOf((*MockContext)(nil).Deadline))
}

// Done mocks base method.
func (m *MockContext) Done() <-chan struct{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Done")
	ret0, _ := ret[0].(<-chan struct{})
	return ret0
}

// Done indicates an expected call of Done.
func (mr *MockContextMockRecorder) Done() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Done", reflect.TypeOf((*MockContext)(nil).Done))
}

// Err mocks base method.
func (m *MockContext) Err() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Err")
	ret0, _ := ret[0].(error)
	return ret0
}

// Err indicates an expected call of Err.
func (mr *MockContextMockRecorder) Err() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Err", reflect.TypeOf((*MockContext)(nil).Err))
}

// LocalAddr mocks base method.
func (m *MockContext) LocalAddr() net.Addr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LocalAddr")
	ret0, _ := ret[0].(net.Addr)
	return ret0
}

// LocalAddr indicates an expected call of LocalAddr.
func (mr *MockContextMockRecorder) LocalAddr() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LocalAddr", reflect.TypeOf((*MockContext)(nil).LocalAddr))
}

// Lock mocks base method.
func (m *MockContext) Lock() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Lock")
}

// Lock indicates an expected call of Lock.
func (mr *MockContextMockRecorder) Lock() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Lock", reflect.TypeOf((*MockContext)(nil).Lock))
}

// Permissions mocks base method.
func (m *MockContext) Permissions() *ssh.Permissions {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Permissions")
	ret0, _ := ret[0].(*ssh.Permissions)
	return ret0
}

// Permissions indicates an expected call of Permissions.
func (mr *MockContextMockRecorder) Permissions() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Permissions", reflect.TypeOf((*MockContext)(nil).Permissions))
}

// RemoteAddr mocks base method.
func (m *MockContext) RemoteAddr() net.Addr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoteAddr")
	ret0, _ := ret[0].(net.Addr)
	return ret0
}

// RemoteAddr indicates an expected call of RemoteAddr.
func (mr *MockContextMockRecorder) RemoteAddr() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoteAddr", reflect.TypeOf((*MockContext)(nil).RemoteAddr))
}

// ServerVersion mocks base method.
func (m *MockContext) ServerVersion() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ServerVersion")
	ret0, _ := ret[0].(string)
	return ret0
}

// ServerVersion indicates an expected call of ServerVersion.
func (mr *MockContextMockRecorder) ServerVersion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ServerVersion", reflect.TypeOf((*MockContext)(nil).ServerVersion))
}

// SessionID mocks base method.
func (m *MockContext) SessionID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SessionID")
	ret0, _ := ret[0].(string)
	return ret0
}

// SessionID indicates an expected call of SessionID.
func (mr *MockContextMockRecorder) SessionID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SessionID", reflect.TypeOf((*MockContext)(nil).SessionID))
}

// SetValue mocks base method.
func (m *MockContext) SetValue(arg0, arg1 any) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetValue", arg0, arg1)
}

// SetValue indicates an expected call of SetValue.
func (mr *MockContextMockRecorder) SetValue(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetValue", reflect.TypeOf((*MockContext)(nil).SetValue), arg0, arg1)
}

// Unlock mocks base method.
func (m *MockContext) Unlock() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Unlock")
}

// Unlock indicates an expected call of Unlock.
func (mr *MockContextMockRecorder) Unlock() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unlock", reflect.TypeOf((*MockContext)(nil).Unlock))
}

// User mocks base method.
func (m *MockContext) User() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "User")
	ret0, _ := ret[0].(string)
	return ret0
}

// User indicates an expected call of User.
func (mr *MockContextMockRecorder) User() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "User", reflect.TypeOf((*MockContext)(nil).User))
}

// Value mocks base method.
func (m *MockContext) Value(arg0 any) any {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Value", arg0)
	ret0, _ := ret[0].(any)
	return ret0
}

// Value indicates an expected call of Value.
func (mr *MockContextMockRecorder) Value(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Value", reflect.TypeOf((*MockContext)(nil).Value), arg0)
}
