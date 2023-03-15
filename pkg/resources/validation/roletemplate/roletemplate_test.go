package roletemplate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/fakes"
	"github.com/rancher/webhook/pkg/resources/validation/roletemplate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	circleRoleTemplateName   = "circleRef"
	adminUser                = "admin-userid"
	testUser                 = "test-userid"
	noPrivUser               = "no-priv-userid"
	notFoundRoleTemplateName = "not-found-roleTemplate"
)

type TableTest struct {
	name    string
	args    args
	allowed bool
}

type args struct {
	oldRT    func() *v3.RoleTemplate
	newRT    func() *v3.RoleTemplate
	username string
}

type RoleTemplateSuite struct {
	suite.Suite
	ruleEmptyVerbs rbacv1.PolicyRule
	adminRT        *v3.RoleTemplate
	readNodesRT    *v3.RoleTemplate
	lockedRT       *v3.RoleTemplate
	adminCR        *rbacv1.ClusterRole
	manageNodeRole *rbacv1.ClusterRole
}

func TestRoleTemplates(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(RoleTemplateSuite))
}

func (c *RoleTemplateSuite) SetupSuite() {
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
	c.ruleEmptyVerbs = rbacv1.PolicyRule{
		Verbs:     nil,
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	c.readNodesRT = &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-role",
		},
		DisplayName: "Read Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods, ruleWriteNodes},
		Context:     "cluster",
	}
	c.adminRT = &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		DisplayName:    "Admin Role",
		Rules:          []rbacv1.PolicyRule{ruleAdmin},
		Builtin:        true,
		Administrative: true,
		Context:        "cluster",
	}
	c.lockedRT = &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-role",
		},
		DisplayName: "Locked Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods},
		Locked:      true,
		Context:     "cluster",
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

func (c *RoleTemplateSuite) Test_PrivilegeEscalation() {
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

	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(c.readNodesRT.Name).Return(c.readNodesRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(notFoundRoleTemplateName).Return(nil, newNotFound(notFoundRoleTemplateName)).AnyTimes()
	roleTemplateCache.EXPECT().List(gomock.Any()).Return([]*v3.RoleTemplate{c.adminRT, c.readNodesRT}, nil).AnyTimes()
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(k8testing.CreateActionImpl)
		review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
		spec := review.Spec
		if spec.User == noPrivUser {
			return true, nil, fmt.Errorf("expected error")
		}

		review.Status.Allowed = spec.User == testUser &&
			spec.ResourceAttributes.Verb == "escalate"
		return true, review, nil
	})

	validator := roletemplate.NewValidator(resolver, roleResolver, fakeSAR)

	tests := []TableTest{
		{
			name: "base test valid privileges",
			args: args{
				username: adminUser,
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.adminCR.Rules
					return baseRT
				},
				oldRT: func() *v3.RoleTemplate { return nil },
			},
			allowed: true,
		},

		{
			name: "binding to equal privilege level",
			args: args{
				username: testUser,
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					return baseRT
				},
				oldRT: func() *v3.RoleTemplate { return nil },
			},
			allowed: true,
		},

		{
			name: "privilege escalation denied",
			args: args{
				username: noPrivUser,
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.adminCR.Rules
					return baseRT
				},
				oldRT: func() *v3.RoleTemplate { return nil },
			},
			allowed: false,
		},

		{
			name: "privilege escalation with escalate",
			args: args{
				username: testUser,
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.adminCR.Rules
					return baseRT
				},
				oldRT: func() *v3.RoleTemplate { return nil },
			},
			allowed: true,
		},

		{
			name: "inherited privileges check",
			args: args{
				username: noPrivUser,
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = nil
					baseRT.RoleTemplateNames = []string{c.readNodesRT.Name}
					return baseRT
				},
				oldRT: func() *v3.RoleTemplate { return nil },
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			req := createRTRequest(c.T(), test.args.oldRT(), test.args.newRT(), test.args.username)
			resp, err := validator.Admit(req)
			if c.NoError(err, "Admit failed") {
				c.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (c *RoleTemplateSuite) Test_UpdateValidation() {
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
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(k8testing.CreateActionImpl)
		review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
		if review.Spec.User == noPrivUser {
			return true, review, fmt.Errorf("expected error")
		}
		review.Status.Allowed = review.Spec.User == adminUser &&
			review.Spec.ResourceAttributes.Verb == auth.ForceUpdate

		return true, review, nil
	})

	validator := roletemplate.NewValidator(resolver, roleResolver, fakeSAR)

	tests := []TableTest{
		{
			name: "base test valid RT annotation update",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Annotations = nil
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Annotations = map[string]string{"foo": "bar"}
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update displayName",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.DisplayName = "old display"
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.DisplayName = "new display"
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update displayName of builtin with",
			args: args{
				username: testUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.DisplayName = "old display"
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.DisplayName = "new display"
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "update displayName of builtin with force-update verb",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.DisplayName = "old display"
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.DisplayName = "new display"
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update custerCreatorDefault of builtin",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.ClusterCreatorDefault = true
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.ClusterCreatorDefault = false
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update projectCreatorDefault of builtin",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.ProjectCreatorDefault = true
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.ProjectCreatorDefault = false
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update projectCreatorDefault of builtin with failed force-update",
			args: args{
				username: noPrivUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.ProjectCreatorDefault = true
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.ProjectCreatorDefault = false
					baseRT.Builtin = true
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update annotation of builtin",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Builtin = true
					baseRT.Annotations = nil
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Builtin = true
					baseRT.Annotations = map[string]string{"foo": "bar"}
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update Builtin field",
			args: args{
				username: testUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Builtin = false
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "update Builtin field with force-update verb",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Builtin = true
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Builtin = false
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update empty rules",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = []rbacv1.PolicyRule{c.ruleEmptyVerbs}
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = []rbacv1.PolicyRule{c.ruleEmptyVerbs}
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "update Context",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Context = "cluster"
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Context = "project"
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "update Administrative of cluster context",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Context = "cluster"
					baseRT.Administrative = false
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Context = "cluster"
					baseRT.Administrative = true
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "update Administrative of non cluster context",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Context = "project"
					baseRT.Administrative = false
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Context = "project"
					baseRT.Administrative = true
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "update empty rules being deleted",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = []rbacv1.PolicyRule{c.ruleEmptyVerbs}
					return baseRT
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = []rbacv1.PolicyRule{c.ruleEmptyVerbs}
					baseRT.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					return baseRT
				},
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			req := createRTRequest(c.T(), test.args.oldRT(), test.args.newRT(), test.args.username)
			resp, err := validator.Admit(req)
			if c.NoError(err, "Admit failed") {
				c.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (c *RoleTemplateSuite) Test_Create() {
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
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}

	validator := roletemplate.NewValidator(resolver, roleResolver, fakeSAR)

	tests := []TableTest{
		{
			name: "base test valid RT",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					return baseRT
				},
			},
			allowed: true,
		},
		{
			name: "missing displayName",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.DisplayName = ""
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "missing rule verbs",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = []rbacv1.PolicyRule{c.ruleEmptyVerbs}
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "missing context",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Context = ""
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "unknown context",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Context = "namespace"
					return baseRT
				},
			},
			allowed: false,
		},
		{
			name: "project context with administrative",
			args: args{
				username: adminUser,
				oldRT: func() *v3.RoleTemplate {
					return nil
				},
				newRT: func() *v3.RoleTemplate {
					baseRT := newDefaultRT()
					baseRT.Rules = c.manageNodeRole.Rules
					baseRT.Administrative = true
					baseRT.Context = "namespace"
					return baseRT
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			// c.T().Parallel()
			req := createRTRequest(c.T(), test.args.oldRT(), test.args.newRT(), test.args.username)
			resp, err := validator.Admit(req)
			c.NoError(err, "Admit failed")
			c.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (c *RoleTemplateSuite) Test_Delete() {
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}

	tests := []struct {
		TableTest
		wantError      bool
		createResolver func(ctrl *gomock.Controller) *auth.RoleTemplateResolver
	}{
		{
			TableTest: TableTest{
				name: "test basic delete",
				args: args{
					username: adminUser,
					oldRT: func() *v3.RoleTemplate {
						return c.readNodesRT
					},
					newRT: func() *v3.RoleTemplate {
						return nil
					},
				},
				allowed: true,
			},
			createResolver: func(ctrl *gomock.Controller) *auth.RoleTemplateResolver {
				roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
				superAdmin := newDefaultRT()
				superAdmin.Name = "super admin"
				superAdmin.Rules = c.manageNodeRole.Rules
				superAdmin.RoleTemplateNames = []string{c.adminRT.Name}
				allRTs := []*v3.RoleTemplate{c.readNodesRT, superAdmin}
				roleTemplateCache.EXPECT().List(gomock.Any()).Return(allRTs, nil).AnyTimes()
				return auth.NewRoleTemplateResolver(roleTemplateCache, nil)
			},
		},
		{
			TableTest: TableTest{
				name: "test inherited delete",
				args: args{
					username: adminUser,
					oldRT: func() *v3.RoleTemplate {
						return c.adminRT
					},
					newRT: func() *v3.RoleTemplate {
						return nil
					},
				},
				allowed: false,
			},

			createResolver: func(ctrl *gomock.Controller) *auth.RoleTemplateResolver {
				roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
				superAdmin := newDefaultRT()
				superAdmin.Name = "super admin"
				superAdmin.Rules = c.manageNodeRole.Rules
				superAdmin.RoleTemplateNames = []string{c.adminRT.Name}
				allRTs := []*v3.RoleTemplate{c.readNodesRT, superAdmin}
				roleTemplateCache.EXPECT().List(gomock.Any()).Return(allRTs, nil).AnyTimes()
				return auth.NewRoleTemplateResolver(roleTemplateCache, nil)
			},
		},
		{
			TableTest: TableTest{
				name: "test fail to list templates",
				args: args{
					username: adminUser,
					oldRT: func() *v3.RoleTemplate {
						return c.adminRT
					},
					newRT: func() *v3.RoleTemplate {
						return nil
					},
				},
			},
			wantError: true,
			createResolver: func(ctrl *gomock.Controller) *auth.RoleTemplateResolver {
				roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
				roleTemplateCache.EXPECT().List(gomock.Any()).Return(nil, fmt.Errorf("test error")).AnyTimes()
				return auth.NewRoleTemplateResolver(roleTemplateCache, nil)
			},
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			ctrl := gomock.NewController(c.T())
			validator := roletemplate.NewValidator(resolver, test.createResolver(ctrl), fakeSAR)
			req := createRTRequest(c.T(), test.args.oldRT(), test.args.newRT(), test.args.username)
			resp, err := validator.Admit(req)
			if test.wantError {
				c.Error(err, "Admit expected an error")
				return
			}
			if !c.NoError(err, "Admit failed") {
				return
			}
			c.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (c *RoleTemplateSuite) Test_ErrorHandling() {
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)
	ctrl := gomock.NewController(c.T())
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}

	validator := roletemplate.NewValidator(resolver, roleResolver, fakeSAR)

	req := createRTRequest(c.T(), newDefaultRT(), newDefaultRT(), testUser)
	req.Operation = v1.Connect
	_, err := validator.Admit(req)
	c.Error(err, "Admit should fail on unknown handled operations")

	req = createRTRequest(c.T(), newDefaultRT(), newDefaultRT(), testUser)
	req.Object = runtime.RawExtension{}
	_, err = validator.Admit(req)

	c.Error(err, "Admit should fail on bad request object")

	newRT := newDefaultRT()
	newRT.RoleTemplateNames = []string{notFoundRoleTemplateName}
	req = createRTRequest(c.T(), nil, newRT, testUser)
	req.Object = runtime.RawExtension{}
	_, err = validator.Admit(req)
	c.Error(err, "Admit should fail on unknown inherited RoleTemplate")
}

func (c *RoleTemplateSuite) Test_CheckCircularRef() {
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

	tests := []struct {
		name           string
		depth          int
		circleDepth    int
		errorDepth     int
		hasCircularRef bool
		errDesired     bool
	}{
		{
			name:           "basic test case - no inheritance, no circular ref or error",
			depth:          0,
			circleDepth:    -1,
			errorDepth:     -1,
			hasCircularRef: false,
			errDesired:     false,
		},
		{
			name:           "basic inheritance case - depth 1 of input is circular",
			depth:          1,
			circleDepth:    0,
			errorDepth:     -1,
			hasCircularRef: true,
			errDesired:     false,
		},
		{
			name:           "self-reference inheritance case - single role template which inherits itself",
			depth:          0,
			circleDepth:    0,
			errorDepth:     -1,
			hasCircularRef: true,
			errDesired:     false,
		},
		{
			name:           "deeply nested inheritance case - role template inherits other templates which eventually becomes circular",
			depth:          3,
			circleDepth:    2,
			errorDepth:     -1,
			hasCircularRef: true,
			errDesired:     false,
		},
		{
			name:           "basic error case - role inherits another role which doesn't exist",
			depth:          1,
			circleDepth:    -1,
			errorDepth:     0,
			hasCircularRef: false,
			errDesired:     true,
		},
	}

	for i := range tests {
		testCase := tests[i]
		c.Run(testCase.name, func() {
			rtName := "input-role"
			if testCase.circleDepth == 0 && testCase.hasCircularRef {
				rtName = circleRoleTemplateName
			}

			ctrl := gomock.NewController(c.T())
			roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
			roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()

			newRT := createNestedRoleTemplate(rtName, roleTemplateCache, testCase.depth, testCase.circleDepth, testCase.errorDepth)

			req := createRTRequest(c.T(), nil, newRT, adminUser)
			clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
			roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
			validator := roletemplate.NewValidator(resolver, roleResolver, fakeSAR)

			resp, err := validator.Admit(req)
			if testCase.errDesired {
				c.Error(err, "circular reference check, expected err")
				return
			}
			c.NoError(err, "circular reference check, did not expect an err")

			if !testCase.hasCircularRef {
				c.True(resp.Allowed, "expected roleTemplate to be allowed")
				return
			}

			c.False(resp.Allowed, "expected roleTemplate to be denied")
			if c.NotNil(resp.Result, "expected response result to be set") {
				c.Contains(resp.Result.Message, circleRoleTemplateName, "response result does not contain circular RoleTemplate name.")
			}
		})
	}
}

func createNestedRoleTemplate(name string, cache *fakes.MockRoleTemplateCache, depth int, circleDepth int, errDepth int) *v3.RoleTemplate {
	start := createRoleTemplate(name)
	prior := start

	if depth == 0 && circleDepth == 0 {
		start.RoleTemplateNames = []string{start.Name}
		cache.EXPECT().Get(start.Name).Return(start, nil).MinTimes(0)
	}
	for i := 0; i < depth; i++ {
		current := createRoleTemplate("current-" + strconv.Itoa(i))
		if i != errDepth {
			cache.EXPECT().Get(current.Name).Return(current, nil).MinTimes(0)
		} else {
			cache.EXPECT().Get(gomock.AssignableToTypeOf(current.Name)).Return(nil, fmt.Errorf("not found")).MinTimes(0)
		}
		priorInherits := []string{current.Name}
		if i == circleDepth {
			circle := createRoleTemplate(circleRoleTemplateName)
			cache.EXPECT().Get(circle.Name).Return(circle, nil).MinTimes(0)
			priorInherits = append(priorInherits, circle.Name)
			circle.RoleTemplateNames = []string{name}
		}
		prior.RoleTemplateNames = priorInherits
		prior = current
	}

	return start
}

func createRoleTemplate(name string) *v3.RoleTemplate {
	newRT := newDefaultRT()
	newRT.Name = name
	newRT.Rules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}
	return newRT
}

// createRTRequest will return a new webhookRequest with the using the given RTs
// if oldRT is nil then a request will be returned as a create operation.
// if newRT is nil then a request will be returned as a delete operation.
// else the request will look like and update operation.
func createRTRequest(t *testing.T, oldRT, newRT *v3.RoleTemplate, username string) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "RoleTemplate"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "roletemplates"}
	req := &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       v1.Create,
			UserInfo:        authenticationv1.UserInfo{Username: username, UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	var err error
	if oldRT != nil {
		req.Operation = v1.Update
		req.Name = oldRT.Name
		req.Namespace = oldRT.Namespace
		req.OldObject.Raw, err = json.Marshal(oldRT)
		assert.NoError(t, err, "Failed to marshal RT while creating request")
	}
	if newRT != nil {
		req.Name = newRT.Name
		req.Namespace = newRT.Namespace
		req.Object.Raw, err = json.Marshal(newRT)
		assert.NoError(t, err, "Failed to marshal RT while creating request")
	} else {
		req.Operation = v1.Delete
	}

	return req
}

func newDefaultRT() *v3.RoleTemplate {
	return &v3.RoleTemplate{
		TypeMeta: metav1.TypeMeta{Kind: "RoleTemplate", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "rt-new",
			GenerateName:      "rt-",
			Namespace:         "c-namespace",
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		DisplayName:           "test-RT",
		Description:           "Test Role Template",
		Context:               "cluster",
		RoleTemplateNames:     nil,
		Builtin:               false,
		External:              false,
		Hidden:                false,
		Locked:                false,
		ClusterCreatorDefault: false,
		ProjectCreatorDefault: false,
		Administrative:        false,
	}
}

func newNotFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "management.cattle.io", Resource: "roleTemplate"}, name)
}
