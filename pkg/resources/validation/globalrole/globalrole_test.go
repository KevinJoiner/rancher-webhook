package globalrole_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/resources/validation/globalrole"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	adminUser = "admin-userid"
	testUser  = "test-userid"
	errorUser = "error-userid"
)

type TableTest struct {
	name    string
	args    args
	allowed bool
}

type args struct {
	oldGR    func() *apisv3.GlobalRole
	newGR    func() *apisv3.GlobalRole
	username string
}

type GlobalRoleBindingSuite struct {
	suite.Suite
	ruleReadPods   rbacv1.PolicyRule
	ruleWriteNodes rbacv1.PolicyRule
	ruleAdmin      rbacv1.PolicyRule
	ruleEmptyVerbs rbacv1.PolicyRule
	adminCR        *rbacv1.ClusterRole
	readPodsCR     *rbacv1.ClusterRole
}

func TestGlobalRoleBindings(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(GlobalRoleBindingSuite))
}

func (c *GlobalRoleBindingSuite) SetupSuite() {
	c.ruleReadPods = rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	c.ruleWriteNodes = rbacv1.PolicyRule{
		Verbs:     []string{"PUT", "CREATE", "UPDATE"},
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	c.ruleEmptyVerbs = rbacv1.PolicyRule{
		Verbs:     nil,
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	c.ruleAdmin = rbacv1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
	c.adminCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		Rules: []rbacv1.PolicyRule{c.ruleAdmin},
	}
	c.readPodsCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "read-pods"},
		Rules:      []rbacv1.PolicyRule{c.ruleReadPods},
	}
}

func (c *GlobalRoleBindingSuite) Test_PrivilegeEscalation() {
	clusterRoles := []*rbacv1.ClusterRole{c.adminCR, c.readPodsCR}

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
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.readPodsCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)
	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	validator := globalrole.NewValidator(resolver, fakeSAR)

	tests := []TableTest{
		// base test, admin user correctly creates a global role
		{
			name: "base test valid privileges",
			args: args{
				username: adminUser,
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = c.adminCR.Rules
					return baseGR
				},
				oldGR: func() *apisv3.GlobalRole { return nil },
			},
			allowed: true,
		},

		// User attempts to create a globalrole with rules equal to one they hold.
		{
			name: "creating with equal privilege level",
			args: args{
				username: testUser,
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = c.readPodsCR.Rules
					return baseGR
				},
				oldGR: func() *apisv3.GlobalRole { return nil },
			},
			allowed: true,
		},

		// User attempts to create a globalrole with more rules than the ones they hold.
		{
			name: "creation with privilege escalation",
			args: args{
				username: testUser,
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = c.adminCR.Rules
					return baseGR
				},
				oldGR: func() *apisv3.GlobalRole { return nil },
			},
			allowed: false,
		},

		// User attempts to update a globalrole with more rules than the ones they hold.
		{
			name: "update with privilege escalation",
			args: args{
				username: testUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = c.readPodsCR.Rules
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = append(baseGR.Rules, c.ruleReadPods, c.ruleWriteNodes)
					return baseGR
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			req := createGRRequest(c.T(), test.args.oldGR(), test.args.newGR(), test.args.username)
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
	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	validator := globalrole.NewValidator(resolver, fakeSAR)
	k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(k8testing.CreateActionImpl)
		review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
		spec := review.Spec
		if spec.User == errorUser {
			return true, nil, fmt.Errorf("expected error")
		}

		review.Status.Allowed = spec.User == adminUser &&
			spec.ResourceAttributes.Verb == auth.ForceUpdate
		return true, review, nil
	})

	tests := []TableTest{
		{
			name: "base test valid GR annotation update",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = c.readPodsCR.Rules
					baseGR.Annotations = nil
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = c.readPodsCR.Rules
					baseGR.Annotations = map[string]string{"foo": "bar"}
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update displayName",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = c.readPodsCR.Rules
					baseGR.DisplayName = "old display"
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = c.readPodsCR.Rules
					baseGR.DisplayName = "new display"
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update displayName of builtin",
			args: args{
				username: testUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = "old display"
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = "new display"
					baseGR.Builtin = true
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "update displayName of builtin with force-update verb",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = "old display"
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = "new display"
					baseGR.Builtin = true
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update newUserDefault of builtin",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NewUserDefault = true
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NewUserDefault = false
					baseGR.Builtin = true
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update newUserDefault of builtin with failed force-update check",
			args: args{
				username: errorUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NewUserDefault = true
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NewUserDefault = false
					baseGR.Builtin = true
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update annotation of builtin",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = c.readPodsCR.Rules
					baseGR.Builtin = true
					baseGR.Annotations = nil
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = c.readPodsCR.Rules
					baseGR.Builtin = true
					baseGR.Annotations = map[string]string{"foo": "bar"}
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update Builtin field",
			args: args{
				username: testUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = false
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "update Builtin field with force-update verb",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = false
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update empty rules",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{c.ruleReadPods, c.ruleEmptyVerbs}
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{c.ruleReadPods, c.ruleEmptyVerbs}
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "update empty rules being deleted",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{c.ruleReadPods, c.ruleEmptyVerbs}
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{c.ruleReadPods, c.ruleEmptyVerbs}
					baseGR.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					return baseGR
				},
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			req := createGRRequest(c.T(), test.args.oldGR(), test.args.newGR(), test.args.username)
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
	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	validator := globalrole.NewValidator(resolver, fakeSAR)

	tests := []TableTest{
		{
			name: "base test valid GR",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					return nil
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{c.ruleWriteNodes}
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "missing displayName",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					return nil
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = ""
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "missing rule verbs",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					return nil
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{c.ruleReadPods, c.ruleEmptyVerbs}
					return baseGR
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			// c.T().Parallel()
			req := createGRRequest(c.T(), test.args.oldGR(), test.args.newGR(), test.args.username)
			resp, err := validator.Admit(req)
			c.NoError(err, "Admit failed")
			c.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (c *GlobalRoleBindingSuite) Test_ErrorHandling() {
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)
	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	validator := globalrole.NewValidator(resolver, fakeSAR)

	req := createGRRequest(c.T(), newDefaultGR(), newDefaultGR(), testUser)
	req.Operation = v1.Connect
	_, err := validator.Admit(req)
	c.Error(err, "Admit should fail on unknown handled operations")

	req = createGRRequest(c.T(), newDefaultGR(), newDefaultGR(), testUser)
	req.Object = runtime.RawExtension{}
	_, err = validator.Admit(req)
	c.Error(err, "Admit should fail on bad request object")
}

// createGRRequest will return a new webhookRequest with the using the given GRs
// if oldGR is nil then a request will be returned as a create operation.
// if newGR is nil then a request will be returned as a delete operation.
// else the request will look like and update operation.
func createGRRequest(t *testing.T, oldGR, newGR *apisv3.GlobalRole, username string) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRole"}
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
	if oldGR != nil {
		req.Operation = v1.Update
		req.Name = oldGR.Name
		req.Namespace = oldGR.Namespace
		req.OldObject.Raw, err = json.Marshal(oldGR)
		assert.NoError(t, err, "Failed to marshal GR while creating request")
	}
	if newGR != nil {
		req.Name = newGR.Name
		req.Namespace = newGR.Namespace
		req.Object.Raw, err = json.Marshal(newGR)
		assert.NoError(t, err, "Failed to marshal GR while creating request")
	} else {
		req.Operation = v1.Delete
	}

	return req
}

func newDefaultGR() *apisv3.GlobalRole {
	return &apisv3.GlobalRole{
		TypeMeta: metav1.TypeMeta{Kind: "GlobalRole", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gr-new",
			GenerateName:      "gr-",
			Namespace:         "c-namespace",
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		DisplayName:    "Test Global Role",
		Description:    "This is a role created for testing.",
		Rules:          nil,
		NewUserDefault: false,
		Builtin:        false,
	}
}
