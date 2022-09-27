package resolvers_test

import (
	"strconv"
	"testing"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/fakes"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resolvers"
	"github.com/stretchr/testify/suite"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

type CRTBResolverSuite struct {
	suite.Suite
	adminRT             *apisv3.RoleTemplate
	readRT              *apisv3.RoleTemplate
	writeRT             *apisv3.RoleTemplate
	user1AdminCRTB      *apisv3.ClusterRoleTemplateBinding
	user1AReadNS2CRTB   *apisv3.ClusterRoleTemplateBinding
	user1InvalidNS2CRTB *apisv3.ClusterRoleTemplateBinding
	user2WriteCRTB      *apisv3.ClusterRoleTemplateBinding
	user2ReadCRTB       *apisv3.ClusterRoleTemplateBinding
}

func TestCRTBResolver(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(CRTBResolverSuite))
}

func (c *CRTBResolverSuite) SetupSuite() {
	ruleReadPods := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	ruleReadServices := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"services"},
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
	c.readRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-role",
		},
		DisplayName: "Read Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods, ruleReadServices},
		Context:     "cluster",
	}
	c.adminRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		DisplayName:    "Admin Role",
		Rules:          []rbacv1.PolicyRule{ruleAdmin},
		Builtin:        true,
		Administrative: true,
		Context:        "cluster",
	}
	c.writeRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-role",
		},
		DisplayName: "Locked Role",
		Rules:       []rbacv1.PolicyRule{ruleWriteNodes},
		Locked:      true,
		Context:     "cluster",
	}
	c.user1AdminCRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user1-admin",
			Namespace: "namespace1",
		},
		UserName:         "user1",
		RoleTemplateName: c.adminRT.Name,
	}
	c.user1AReadNS2CRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user1-read",
			Namespace: "namespace2",
		},
		UserName:         "user1",
		RoleTemplateName: c.readRT.Name,
	}
	c.user1InvalidNS2CRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user1-invalid",
			Namespace: "namespace2",
		},
		UserName:         "user1",
		RoleTemplateName: invalidName,
	}
	c.user2WriteCRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user2-write",
			Namespace: "namespace1",
		},
		UserName:         "user2",
		RoleTemplateName: c.writeRT.Name,
	}
	c.user2ReadCRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user2-read",
			Namespace: "namespace1",
		},
		UserName:         "user2",
		RoleTemplateName: c.readRT.Name,
	}

}

func (c *CRTBResolverSuite) TestCRTBRuleResolver() {
	ctrl := gomock.NewController(c.T())
	resolver := c.NewTestCRTBResolver(ctrl)
	tests := []struct {
		name      string
		user      user.Info
		namespace string
		wantRules Rules
		wantErr   bool
	}{
		// user with one CRTB in the namespace
		{
			name:      "single CRTB rules",
			user:      NewUserInfo(c.user1AdminCRTB.UserName),
			namespace: c.user1AdminCRTB.Namespace,
			wantRules: c.adminRT.Rules,
		},
		// user that belongs to no CRTBs no rules
		{
			name:      "user with no rules",
			user:      NewUserInfo("invalidUser"),
			namespace: c.user1AdminCRTB.Namespace,
			wantRules: nil,
		},
		// users with CRTB in different namespace no rules
		{
			name:      "user with no rules in namespace",
			user:      NewUserInfo(c.user2WriteCRTB.UserName),
			namespace: c.user1AReadNS2CRTB.Namespace,
			wantRules: nil,
		},
		// user with two CRTB
		{
			name:      "user with multiple CRTB",
			user:      NewUserInfo(c.user2ReadCRTB.UserName),
			namespace: c.user2ReadCRTB.Namespace,
			wantRules: append(c.readRT.Rules, c.writeRT.Rules...),
		},
		// users with one valid and one invalid CRTB partial rules
		{
			name:      "partial rules",
			user:      NewUserInfo(c.user1InvalidNS2CRTB.UserName),
			namespace: c.user1InvalidNS2CRTB.Namespace,
			wantRules: c.readRT.Rules,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		c.Run(tt.name, func() {
			gotRules, err := resolver.RulesFor(tt.user, tt.namespace)
			if tt.wantErr {
				c.Errorf(err, "CRTBRuleResolver.RulesFor() error = %v, wantErr %v", err, tt.wantErr)
				// still check result because function is suppose to return partial results.

				if !tt.wantRules.Equal(gotRules) {
					c.Fail("List of rules did not match", "wanted=%+v got=%+v", tt.wantRules, gotRules)
				}
				return
			}
			c.NoError(err, "unexpected error")
			if !tt.wantRules.Equal(gotRules) {
				c.Fail("List of rules did not match", "wanted=%+v got=%+v", tt.wantRules, gotRules)
			}
		})
	}
}
func (c *CRTBResolverSuite) NewTestCRTBResolver(ctrl *gomock.Controller) *resolvers.CRTBRuleResolver {
	bindings := []*apisv3.ClusterRoleTemplateBinding{c.user1AdminCRTB, c.user1AReadNS2CRTB, c.user1InvalidNS2CRTB, c.user2WriteCRTB, c.user2ReadCRTB}
	crtbCache := NewCRTBCache(ctrl, bindings)
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(c.readRT.Name).Return(c.readRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(c.writeRT.Name).Return(c.writeRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(invalidName).Return(nil, errNotFound).AnyTimes()
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	return resolvers.NewCRTBRuleResolver(crtbCache, roleResolver)
}

func NewCRTBCache(ctrl *gomock.Controller, bindings []*apisv3.ClusterRoleTemplateBinding) v3.ClusterRoleTemplateBindingCache {
	clusterCache := fakes.NewMockClusterRoleTemplateBindingCache(ctrl)

	clusterCache.EXPECT().Get(gomock.Any(), gomock.Any()).DoAndReturn(func(namespace, name string) (*apisv3.ClusterRoleTemplateBinding, error) {
		for _, binding := range bindings {
			if binding.Namespace == namespace && binding.Name == name {
				return binding, nil
			}
		}
		return nil, errNotFound
	}).AnyTimes()

	clusterCache.EXPECT().List(gomock.Any(), gomock.Any()).DoAndReturn(func(namespace string, _ interface{}) ([]*apisv3.ClusterRoleTemplateBinding, error) {
		retList := []*apisv3.ClusterRoleTemplateBinding{}
		for _, binding := range bindings {
			if binding.Namespace == namespace {
				retList = append(retList, binding)
			}
		}
		return retList, nil
	}).AnyTimes()

	return clusterCache
}

var result []rbacv1.PolicyRule

func BenchmarkGotRules(b *testing.B) {
	cSuite := &CRTBResolverSuite{}
	ctrl := gomock.NewController(b)
	resolver := setupBench(ctrl, cSuite)
	var rules []rbacv1.PolicyRule
	for i := 0; i < b.N; i++ {
		rules, _ = resolver.RulesFor(NewUserInfo(cSuite.user1AdminCRTB.UserName), cSuite.user1AdminCRTB.Namespace)
	}
	result = rules
}

func BenchmarkGotRulesWithMapCheck(b *testing.B) {
	cSuite := &CRTBResolverSuite{}
	ctrl := gomock.NewController(b)
	resolver := setupBench(ctrl, cSuite)
	var rules []rbacv1.PolicyRule
	for i := 0; i < b.N; i++ {
		rules, _ = resolver.RulesFor2(NewUserInfo(cSuite.user1AdminCRTB.UserName), cSuite.user1AdminCRTB.Namespace)
	}
	result = rules
}

func BenchmarkGotRulesWithMapOverride(b *testing.B) {
	cSuite := &CRTBResolverSuite{}
	ctrl := gomock.NewController(b)
	resolver := setupBench(ctrl, cSuite)
	var rules []rbacv1.PolicyRule
	for i := 0; i < b.N; i++ {
		rules, _ = resolver.RulesFor3(NewUserInfo(cSuite.user1AdminCRTB.UserName), cSuite.user1AdminCRTB.Namespace)
	}
	result = rules
}

func createNestedRoleTemplate(name string, cache *fakes.MockRoleTemplateCache, depth, numOfRules int) *apisv3.RoleTemplate {
	defaultRules := make([]rbacv1.PolicyRule, 0, numOfRules)
	for i := 0; i < numOfRules; i++ {
		defaultRules = append(defaultRules, rbacv1.PolicyRule{
			Verbs:     []string{"GET", "WATCH"},
			APIGroups: []string{"v1"},
			Resources: []string{"services"},
		})
	}

	start := createRoleTemplate(name, defaultRules)
	prior := start

	for i := 0; i < depth; i++ {
		current := createRoleTemplate("current-"+strconv.Itoa(i), defaultRules)
		cache.EXPECT().Get(current.Name).Return(current, nil).AnyTimes()
		priorInherits := []string{current.Name}
		prior.RoleTemplateNames = priorInherits
		prior = current
	}

	return start
}

func createRoleTemplate(name string, rules []rbacv1.PolicyRule) *apisv3.RoleTemplate {
	return &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Rules: rules,
	}
}

func setupBench(ctrl *gomock.Controller, c *CRTBResolverSuite) *resolvers.CRTBRuleResolver {
	c.SetupSuite()
	bindings := []*apisv3.ClusterRoleTemplateBinding{c.user1AdminCRTB}
	crtbCache := NewCRTBCache(ctrl, bindings)
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	rt := createNestedRoleTemplate(c.adminRT.Name, roleTemplateCache, 10, 100)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(rt, nil).AnyTimes()
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	return resolvers.NewCRTBRuleResolver(crtbCache, roleResolver)
}
