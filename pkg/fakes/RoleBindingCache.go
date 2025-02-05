// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1 (interfaces: RoleBindingCache,RoleBindingController)

// Package fakes is a generated GoMock package.
package fakes

import (
	context "context"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	v1 "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	generic "github.com/rancher/wrangler/pkg/generic"
	v10 "k8s.io/api/rbac/v1"
	v11 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// MockRoleBindingCache is a mock of RoleBindingCache interface.
type MockRoleBindingCache struct {
	ctrl     *gomock.Controller
	recorder *MockRoleBindingCacheMockRecorder
}

// MockRoleBindingCacheMockRecorder is the mock recorder for MockRoleBindingCache.
type MockRoleBindingCacheMockRecorder struct {
	mock *MockRoleBindingCache
}

// NewMockRoleBindingCache creates a new mock instance.
func NewMockRoleBindingCache(ctrl *gomock.Controller) *MockRoleBindingCache {
	mock := &MockRoleBindingCache{ctrl: ctrl}
	mock.recorder = &MockRoleBindingCacheMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRoleBindingCache) EXPECT() *MockRoleBindingCacheMockRecorder {
	return m.recorder
}

// AddIndexer mocks base method.
func (m *MockRoleBindingCache) AddIndexer(arg0 string, arg1 v1.RoleBindingIndexer) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddIndexer", arg0, arg1)
}

// AddIndexer indicates an expected call of AddIndexer.
func (mr *MockRoleBindingCacheMockRecorder) AddIndexer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddIndexer", reflect.TypeOf((*MockRoleBindingCache)(nil).AddIndexer), arg0, arg1)
}

// Get mocks base method.
func (m *MockRoleBindingCache) Get(arg0, arg1 string) (*v10.RoleBinding, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1)
	ret0, _ := ret[0].(*v10.RoleBinding)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockRoleBindingCacheMockRecorder) Get(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockRoleBindingCache)(nil).Get), arg0, arg1)
}

// GetByIndex mocks base method.
func (m *MockRoleBindingCache) GetByIndex(arg0, arg1 string) ([]*v10.RoleBinding, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByIndex", arg0, arg1)
	ret0, _ := ret[0].([]*v10.RoleBinding)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByIndex indicates an expected call of GetByIndex.
func (mr *MockRoleBindingCacheMockRecorder) GetByIndex(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByIndex", reflect.TypeOf((*MockRoleBindingCache)(nil).GetByIndex), arg0, arg1)
}

// List mocks base method.
func (m *MockRoleBindingCache) List(arg0 string, arg1 labels.Selector) ([]*v10.RoleBinding, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", arg0, arg1)
	ret0, _ := ret[0].([]*v10.RoleBinding)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockRoleBindingCacheMockRecorder) List(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockRoleBindingCache)(nil).List), arg0, arg1)
}

// MockRoleBindingController is a mock of RoleBindingController interface.
type MockRoleBindingController struct {
	ctrl     *gomock.Controller
	recorder *MockRoleBindingControllerMockRecorder
}

// MockRoleBindingControllerMockRecorder is the mock recorder for MockRoleBindingController.
type MockRoleBindingControllerMockRecorder struct {
	mock *MockRoleBindingController
}

// NewMockRoleBindingController creates a new mock instance.
func NewMockRoleBindingController(ctrl *gomock.Controller) *MockRoleBindingController {
	mock := &MockRoleBindingController{ctrl: ctrl}
	mock.recorder = &MockRoleBindingControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRoleBindingController) EXPECT() *MockRoleBindingControllerMockRecorder {
	return m.recorder
}

// AddGenericHandler mocks base method.
func (m *MockRoleBindingController) AddGenericHandler(arg0 context.Context, arg1 string, arg2 generic.Handler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddGenericHandler", arg0, arg1, arg2)
}

// AddGenericHandler indicates an expected call of AddGenericHandler.
func (mr *MockRoleBindingControllerMockRecorder) AddGenericHandler(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddGenericHandler", reflect.TypeOf((*MockRoleBindingController)(nil).AddGenericHandler), arg0, arg1, arg2)
}

// AddGenericRemoveHandler mocks base method.
func (m *MockRoleBindingController) AddGenericRemoveHandler(arg0 context.Context, arg1 string, arg2 generic.Handler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddGenericRemoveHandler", arg0, arg1, arg2)
}

// AddGenericRemoveHandler indicates an expected call of AddGenericRemoveHandler.
func (mr *MockRoleBindingControllerMockRecorder) AddGenericRemoveHandler(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddGenericRemoveHandler", reflect.TypeOf((*MockRoleBindingController)(nil).AddGenericRemoveHandler), arg0, arg1, arg2)
}

// Cache mocks base method.
func (m *MockRoleBindingController) Cache() v1.RoleBindingCache {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Cache")
	ret0, _ := ret[0].(v1.RoleBindingCache)
	return ret0
}

// Cache indicates an expected call of Cache.
func (mr *MockRoleBindingControllerMockRecorder) Cache() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cache", reflect.TypeOf((*MockRoleBindingController)(nil).Cache))
}

// Create mocks base method.
func (m *MockRoleBindingController) Create(arg0 *v10.RoleBinding) (*v10.RoleBinding, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", arg0)
	ret0, _ := ret[0].(*v10.RoleBinding)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockRoleBindingControllerMockRecorder) Create(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockRoleBindingController)(nil).Create), arg0)
}

// Delete mocks base method.
func (m *MockRoleBindingController) Delete(arg0, arg1 string, arg2 *v11.DeleteOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockRoleBindingControllerMockRecorder) Delete(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockRoleBindingController)(nil).Delete), arg0, arg1, arg2)
}

// Enqueue mocks base method.
func (m *MockRoleBindingController) Enqueue(arg0, arg1 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Enqueue", arg0, arg1)
}

// Enqueue indicates an expected call of Enqueue.
func (mr *MockRoleBindingControllerMockRecorder) Enqueue(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Enqueue", reflect.TypeOf((*MockRoleBindingController)(nil).Enqueue), arg0, arg1)
}

// EnqueueAfter mocks base method.
func (m *MockRoleBindingController) EnqueueAfter(arg0, arg1 string, arg2 time.Duration) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "EnqueueAfter", arg0, arg1, arg2)
}

// EnqueueAfter indicates an expected call of EnqueueAfter.
func (mr *MockRoleBindingControllerMockRecorder) EnqueueAfter(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EnqueueAfter", reflect.TypeOf((*MockRoleBindingController)(nil).EnqueueAfter), arg0, arg1, arg2)
}

// Get mocks base method.
func (m *MockRoleBindingController) Get(arg0, arg1 string, arg2 v11.GetOptions) (*v10.RoleBinding, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1, arg2)
	ret0, _ := ret[0].(*v10.RoleBinding)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockRoleBindingControllerMockRecorder) Get(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockRoleBindingController)(nil).Get), arg0, arg1, arg2)
}

// GroupVersionKind mocks base method.
func (m *MockRoleBindingController) GroupVersionKind() schema.GroupVersionKind {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GroupVersionKind")
	ret0, _ := ret[0].(schema.GroupVersionKind)
	return ret0
}

// GroupVersionKind indicates an expected call of GroupVersionKind.
func (mr *MockRoleBindingControllerMockRecorder) GroupVersionKind() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GroupVersionKind", reflect.TypeOf((*MockRoleBindingController)(nil).GroupVersionKind))
}

// Informer mocks base method.
func (m *MockRoleBindingController) Informer() cache.SharedIndexInformer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Informer")
	ret0, _ := ret[0].(cache.SharedIndexInformer)
	return ret0
}

// Informer indicates an expected call of Informer.
func (mr *MockRoleBindingControllerMockRecorder) Informer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Informer", reflect.TypeOf((*MockRoleBindingController)(nil).Informer))
}

// List mocks base method.
func (m *MockRoleBindingController) List(arg0 string, arg1 v11.ListOptions) (*v10.RoleBindingList, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", arg0, arg1)
	ret0, _ := ret[0].(*v10.RoleBindingList)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockRoleBindingControllerMockRecorder) List(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockRoleBindingController)(nil).List), arg0, arg1)
}

// OnChange mocks base method.
func (m *MockRoleBindingController) OnChange(arg0 context.Context, arg1 string, arg2 v1.RoleBindingHandler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnChange", arg0, arg1, arg2)
}

// OnChange indicates an expected call of OnChange.
func (mr *MockRoleBindingControllerMockRecorder) OnChange(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnChange", reflect.TypeOf((*MockRoleBindingController)(nil).OnChange), arg0, arg1, arg2)
}

// OnRemove mocks base method.
func (m *MockRoleBindingController) OnRemove(arg0 context.Context, arg1 string, arg2 v1.RoleBindingHandler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnRemove", arg0, arg1, arg2)
}

// OnRemove indicates an expected call of OnRemove.
func (mr *MockRoleBindingControllerMockRecorder) OnRemove(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnRemove", reflect.TypeOf((*MockRoleBindingController)(nil).OnRemove), arg0, arg1, arg2)
}

// Patch mocks base method.
func (m *MockRoleBindingController) Patch(arg0, arg1 string, arg2 types.PatchType, arg3 []byte, arg4 ...string) (*v10.RoleBinding, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1, arg2, arg3}
	for _, a := range arg4 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Patch", varargs...)
	ret0, _ := ret[0].(*v10.RoleBinding)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Patch indicates an expected call of Patch.
func (mr *MockRoleBindingControllerMockRecorder) Patch(arg0, arg1, arg2, arg3 interface{}, arg4 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1, arg2, arg3}, arg4...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Patch", reflect.TypeOf((*MockRoleBindingController)(nil).Patch), varargs...)
}

// Update mocks base method.
func (m *MockRoleBindingController) Update(arg0 *v10.RoleBinding) (*v10.RoleBinding, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", arg0)
	ret0, _ := ret[0].(*v10.RoleBinding)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Update indicates an expected call of Update.
func (mr *MockRoleBindingControllerMockRecorder) Update(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockRoleBindingController)(nil).Update), arg0)
}

// Updater mocks base method.
func (m *MockRoleBindingController) Updater() generic.Updater {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Updater")
	ret0, _ := ret[0].(generic.Updater)
	return ret0
}

// Updater indicates an expected call of Updater.
func (mr *MockRoleBindingControllerMockRecorder) Updater() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Updater", reflect.TypeOf((*MockRoleBindingController)(nil).Updater))
}

// Watch mocks base method.
func (m *MockRoleBindingController) Watch(arg0 string, arg1 v11.ListOptions) (watch.Interface, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Watch", arg0, arg1)
	ret0, _ := ret[0].(watch.Interface)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Watch indicates an expected call of Watch.
func (mr *MockRoleBindingControllerMockRecorder) Watch(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Watch", reflect.TypeOf((*MockRoleBindingController)(nil).Watch), arg0, arg1)
}
