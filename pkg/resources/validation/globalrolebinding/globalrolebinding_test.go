package globalrolebinding_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/fakes"
	"github.com/rancher/webhook/pkg/resources/validation/globalrolebinding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	adminUser              = "admin-userid"
	testUser               = "test-userid"
	noPrivUser             = "no-priv-userid"
	newUser                = "newUser-userid"
	newGroupPrinc          = "local://group"
	testGroup              = "testGroup"
	notFoundGlobalRoleName = "not-found-globalRole"
)

var errTest = errors.New("bad error")

type TableTest struct {
	name    string
	args    args
	allowed bool
}

type args struct {
	oldGRB   func() *apisv3.GlobalRoleBinding
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

func (c *GlobalRoleBindingSuite) SetupSuite() {
	ruleReadPods := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	ruleWriteNodes := rbacv1.PolicyRule{
		Verbs:     []string{"PUT", "CREATE", "UPDATE"},
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	ruleAdmin := rbacv1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
	c.manageNodesGR = &apisv3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-role",
		},
		DisplayName: "Read Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods, ruleWriteNodes},
	}
	c.adminGR = &apisv3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		DisplayName: "Admin Role",
		Rules:       []rbacv1.PolicyRule{ruleAdmin},
		Builtin:     true,
	}
	c.adminCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		Rules: []rbacv1.PolicyRule{ruleAdmin},
	}
	c.manageNodeRole = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "manage-nodes"},
		Rules:      []rbacv1.PolicyRule{ruleReadPods, ruleWriteNodes},
	}
}

func (c *GlobalRoleBindingSuite) Test_PrivilegeEscalation() {
	clusterRoles := []*rbacv1.ClusterRole{c.adminCR, c.manageNodeRole}

	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.adminCR.Name},
		},
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: testUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.manageNodeRole.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(c.T())
	globalRoleCache := fakes.NewMockGlobalRoleCache(ctrl)
	globalRoleCache.EXPECT().Get(c.adminGR.Name).Return(c.adminGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(c.manageNodesGR.Name).Return(c.manageNodesGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(notFoundGlobalRoleName).Return(nil, newNotFound(notFoundGlobalRoleName)).AnyTimes()
	globalRoleCache.EXPECT().Get("").Return(nil, newNotFound("")).AnyTimes()

	validator := globalrolebinding.NewValidator(globalRoleCache, resolver)

	tests := []TableTest{
		// base test, admin user correctly binding a different user to a globalRole {PASS}.
		{
			name: "base test valid privileges",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = testUser
					baseGRB.GlobalRoleName = c.adminGR.Name
					return baseGRB
				},
				oldGRB: func() *apisv3.GlobalRoleBinding { return nil },
			},
			allowed: true,
		},

		// Test user escalates privileges to match their own {PASS}.
		{
			name: "binding to equal privilege level",
			args: args{
				username: testUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = noPrivUser
					baseGRB.GlobalRoleName = c.manageNodesGR.Name
					return baseGRB
				},
				oldGRB: func() *apisv3.GlobalRoleBinding { return nil },
			},
			allowed: true,
		},

		// Test user escalates privileges of another users that is greater then privileges held by the test user. {FAIL}.
		{
			name: "privilege escalation other user",
			args: args{
				username: testUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = noPrivUser
					baseGRB.GlobalRoleName = c.adminGR.Name
					return baseGRB
				},
				oldGRB: func() *apisv3.GlobalRoleBinding { return nil },
			},
			allowed: false,
		},

		// Users attempting to privilege escalate themselves  {FAIL}.
		{
			name: "privilege escalation self",
			args: args{
				username: testUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = testUser
					baseGRB.GlobalRoleName = c.adminGR.Name
					return baseGRB
				},
				oldGRB: func() *apisv3.GlobalRoleBinding { return nil },
			},
			allowed: false,
		},

		// Test that the privileges evaluated are those of the user in the request not the user being bound.  {FAIL}.
		{
			name: "correct user privileges are evaluated.",
			args: args{
				username: testUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					baseGRB.GlobalRoleName = c.adminGR.Name
					return baseGRB
				},
				oldGRB: func() *apisv3.GlobalRoleBinding { return nil },
			},
			allowed: false,
		},

		// Test that if global role can not be found we reject the request.  {FAIL}.
		{
			name: "unknown globalRole",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
			},
			allowed: false,
		},

		// Test that if global role can not be found and we the operation is a delete operation we allow the request.  {PASS}.
		{
			name: "unknown globalRole being deleted",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			req := createGRBRequest(c.T(), test.args.oldGRB(), test.args.newGRB(), test.args.username)
			resp, err := validator.Admit(req)
			c.NoError(err, "Admit failed")
			c.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (c *GlobalRoleBindingSuite) Test_UpdateValidation() {
	clusterRoles := []*rbacv1.ClusterRole{c.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(c.T())
	globalRoleCache := fakes.NewMockGlobalRoleCache(ctrl)
	globalRoleCache.EXPECT().Get(c.adminGR.Name).Return(c.adminGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(notFoundGlobalRoleName).Return(nil, newNotFound(notFoundGlobalRoleName)).AnyTimes()

	validator := globalrolebinding.NewValidator(globalRoleCache, resolver)

	tests := []TableTest{
		{
			name: "base test valid GRB annotation update",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.Annotations = nil
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.Annotations = map[string]string{"foo": "bar"}
					return baseGRB
				},
			},
			allowed: true,
		},
		{
			name: "update GlobalRole",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = c.manageNodesGR.Name
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = c.adminGR.Name
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "unknown globalRole",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "unknown globalRole that is being deleted",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					baseGRB.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					return baseGRB
				},
			},
			allowed: true,
		},
		{
			name: "update previously set user",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = newUser
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset user and set group ",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = newUser
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "update previously set group principal",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = newGroupPrinc
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset group and set user ",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					baseGRB.GroupPrincipalName = ""
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					baseGRB.GroupPrincipalName = newGroupPrinc
					return baseGRB
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			req := createGRBRequest(c.T(), test.args.oldGRB(), test.args.newGRB(), test.args.username)
			resp, err := validator.Admit(req)
			c.NoError(err, "Admit failed")
			c.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (c *GlobalRoleBindingSuite) Test_Create() {
	clusterRoles := []*rbacv1.ClusterRole{c.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(c.T())
	globalRoleCache := fakes.NewMockGlobalRoleCache(ctrl)
	globalRoleCache.EXPECT().Get(c.adminGR.Name).Return(c.adminGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(notFoundGlobalRoleName).Return(nil, newNotFound(notFoundGlobalRoleName)).AnyTimes()
	globalRoleCache.EXPECT().Get("").Return(nil, newNotFound(notFoundGlobalRoleName)).AnyTimes()

	validator := globalrolebinding.NewValidator(globalRoleCache, resolver)

	tests := []TableTest{
		{
			name: "base test valid GRB",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					return baseGRB
				},
			},
			allowed: true,
		},
		{
			name: "missing globalRole name",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = ""
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "missing user and group",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = ""
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "both user and group set",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = testUser
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "Group set but not user",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
			},
			allowed: true,
		},
		{
			name: "unknown globalRole",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			// c.T().Parallel()
			req := createGRBRequest(c.T(), test.args.oldGRB(), test.args.newGRB(), test.args.username)
			resp, err := validator.Admit(req)
			c.NoError(err, "Admit failed")
			c.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (c *GlobalRoleBindingSuite) Test_ErrorHandling() {
	const badGR = "badGR"

	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)

	ctrl := gomock.NewController(c.T())
	globalRoleCache := fakes.NewMockGlobalRoleCache(ctrl)
	globalRoleCache.EXPECT().Get(badGR).Return(nil, errTest)

	validator := globalrolebinding.NewValidator(globalRoleCache, resolver)

	req := createGRBRequest(c.T(), newDefaultGRB(), newDefaultGRB(), testUser)
	req.Operation = v1.Connect
	_, err := validator.Admit(req)
	c.Error(err, "Admit should fail on unknown handled operations")

	req = createGRBRequest(c.T(), newDefaultGRB(), newDefaultGRB(), testUser)
	req.Object = runtime.RawExtension{}
	_, err = validator.Admit(req)
	c.Error(err, "Admit should fail on bad request object")

	newGRB := newDefaultGRB()
	newGRB.GlobalRoleName = badGR
	req = createGRBRequest(c.T(), nil, newGRB, testUser)
	_, err = validator.Admit(req)
	c.Error(err, "Admit should fail on GlobalRole Get error")
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
			Namespace:         "c-namespace",
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
