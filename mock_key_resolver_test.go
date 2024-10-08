// Code generated by mockery v2.42.1. DO NOT EDIT.

package httpsig

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// KeyResolverMock is an autogenerated mock type for the KeyResolver type
type KeyResolverMock struct {
	mock.Mock
}

type KeyResolverMock_Expecter struct {
	mock *mock.Mock
}

func (_m *KeyResolverMock) EXPECT() *KeyResolverMock_Expecter {
	return &KeyResolverMock_Expecter{mock: &_m.Mock}
}

// ResolveKey provides a mock function with given fields: ctx, keyID
func (_m *KeyResolverMock) ResolveKey(ctx context.Context, keyID string) (Key, error) {
	ret := _m.Called(ctx, keyID)

	if len(ret) == 0 {
		panic("no return value specified for ResolveKey")
	}

	var r0 Key
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (Key, error)); ok {
		return rf(ctx, keyID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) Key); ok {
		r0 = rf(ctx, keyID)
	} else {
		r0 = ret.Get(0).(Key)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, keyID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// KeyResolverMock_ResolveKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ResolveKey'
type KeyResolverMock_ResolveKey_Call struct {
	*mock.Call
}

// ResolveKey is a helper method to define mock.On call
//   - ctx context.Context
//   - keyID string
func (_e *KeyResolverMock_Expecter) ResolveKey(ctx interface{}, keyID interface{}) *KeyResolverMock_ResolveKey_Call {
	return &KeyResolverMock_ResolveKey_Call{Call: _e.mock.On("ResolveKey", ctx, keyID)}
}

func (_c *KeyResolverMock_ResolveKey_Call) Run(run func(ctx context.Context, keyID string)) *KeyResolverMock_ResolveKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *KeyResolverMock_ResolveKey_Call) Return(_a0 Key, _a1 error) *KeyResolverMock_ResolveKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *KeyResolverMock_ResolveKey_Call) RunAndReturn(run func(context.Context, string) (Key, error)) *KeyResolverMock_ResolveKey_Call {
	_c.Call.Return(run)
	return _c
}

// NewKeyResolverMock creates a new instance of KeyResolverMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewKeyResolverMock(t interface {
	mock.TestingT
	Cleanup(func())
}) *KeyResolverMock {
	mock := &KeyResolverMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
