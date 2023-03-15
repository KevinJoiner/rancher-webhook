package globalrolebinding_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/fakes"
	"github.com/rancher/webhook/pkg/resources/mutation/globalrolebinding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type TableTest struct {
	name      string
	args      args
	wantGRB   func() *apisv3.GlobalRoleBinding
	allowed   bool
	wantError bool
}

type args struct {
	newGRB   func() *apisv3.GlobalRoleBinding
	username string
}

type GlobalRoleBindingSuite struct {
	suite.Suite
	adminGR        *apisv3.GlobalRole
	manageNodesGR  *apisv3.GlobalRole
	adminCR        *rbacv1.ClusterRole
	manageNodeRole *rbacv1.ClusterRole
}

func TestGlobalRoleBindings(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(GlobalRoleBindingSuite))
}

func (m *GlobalRoleBindingSuite) SetupSuite() {
	ruleAdmin := rbacv1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
	m.adminGR = &apisv3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
			UID:  "01001011 01001010",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "GlobalRole",
			APIVersion: "v3",
		},
		DisplayName: "Admin Role",
		Rules:       []rbacv1.PolicyRule{ruleAdmin},
		Builtin:     true,
	}
}

func (m *GlobalRoleBindingSuite) Test_Create() {

	const adminUser = "admin-userid"
	const notFoundGlobalRoleName = "not-found-globalRole"
	const errorGlobalRoleName = "err-globalRole"
	var errTest = errors.New("bad error")

	ctrl := gomock.NewController(m.T())
	globalRoleCache := fakes.NewMockGlobalRoleCache(ctrl)
	globalRoleCache.EXPECT().Get(m.adminGR.Name).Return(m.adminGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(notFoundGlobalRoleName).Return(nil, newNotFound(notFoundGlobalRoleName)).AnyTimes()
	globalRoleCache.EXPECT().Get(errorGlobalRoleName).Return(nil, errTest).AnyTimes()

	validator := globalrolebinding.NewMutator(globalRoleCache)

	tests := []TableTest{
		{
			name: "base test valid GRB",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = m.adminGR.Name
					baseGRB.Annotations = nil
					return baseGRB
				},
			},
			wantGRB: func() *apisv3.GlobalRoleBinding {
				baseGRB := newDefaultGRB()
				baseGRB.Annotations = map[string]string{
					"cleanup.cattle.io/grbUpgradeCluster": "true",
				}
				baseGRB.OwnerReferences = []metav1.OwnerReference{
					{
						APIVersion: m.adminGR.APIVersion,
						Kind:       m.adminGR.Kind,
						Name:       m.adminGR.Name,
						UID:        m.adminGR.UID,
					},
				}
				return baseGRB
			},
			allowed: true,
		},
		{
			name: "not found global role",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "failed Global Role get",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = errorGlobalRoleName
					return baseGRB
				},
			},
			wantError: true,
		},
	}

	for i := range tests {
		test := tests[i]
		m.Run(test.name, func() {
			req := createGRBRequest(m.T(), nil, test.args.newGRB(), test.args.username)
			resp, err := validator.Admit(req)
			if test.wantError {
				m.Error(err, "expected error from Admit")
				return
			}
			m.NoError(err, "Admit failed")
			m.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
			if test.wantGRB != nil {
				patchObj, err := jsonpatch.DecodePatch(resp.Patch)
				m.Require().NoError(err, "failed to decode patch from response")

				patchedJS, err := patchObj.Apply(req.Object.Raw)
				gotObj := &apisv3.GlobalRoleBinding{}
				err = json.Unmarshal(patchedJS, gotObj)
				m.Require().NoError(err, "failed to unmarshall patched Object")
				m.True(equality.Semantic.DeepEqual(test.wantGRB(), gotObj), "patched object and desired object are not equivalent wanted=%#v got=%#v", test.wantGRB(), gotObj)
			}
		})
	}
}

// createGRBRequest will return a new webhookRequest with the using the given GRBs
// if oldGRB is nil then a request will be returned as a create operation.
// if newGRB is nil then a request will be returned as a delete operation.
// else the request will look like and update operation.
func createGRBRequest(t *testing.T, oldGRB, newGRB *apisv3.GlobalRoleBinding, username string) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRoleBinding"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "globalrolebindings"}
	req := &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       v1.Create,
			UserInfo:        v1authentication.UserInfo{Username: username, UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	var err error
	if oldGRB != nil {
		req.Operation = v1.Update
		req.Name = oldGRB.Name
		req.Namespace = oldGRB.Namespace
		req.OldObject.Raw, err = json.Marshal(oldGRB)
		assert.NoError(t, err, "Failed to marshal GRB while creating request")
	}
	if newGRB != nil {
		req.Name = newGRB.Name
		req.Namespace = newGRB.Namespace
		req.Object.Raw, err = json.Marshal(newGRB)
		assert.NoError(t, err, "Failed to marshal GRB while creating request")
	} else {
		req.Operation = v1.Delete
	}

	return req
}

func newDefaultGRB() *apisv3.GlobalRoleBinding {
	return &apisv3.GlobalRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalRoleBinding", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "grb-new",
			GenerateName:      "grb-",
			Namespace:         "m-namespace",
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		UserName:       "user1",
		GlobalRoleName: "admin-role",
	}
}

func newNotFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "management.cattle.io", Resource: "globalRole"}, name)
}
