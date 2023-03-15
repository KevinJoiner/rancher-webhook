// Package roletemplate handles the validation of request made to roletemplates.management.cattle.io.
package roletemplate

import (
	"fmt"
	"net/http"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/validation"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	rbacvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

const (
	clusterContext = "cluster"
	projectContext = "project"
)

var roleTemplateGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "roletemplates",
}

// NewValidator returns a new admission.ValidatingAdmissionHandler for validation of RoleTemplates.
func NewValidator(resolver rbacvalidation.AuthorizationRuleResolver,
	roleTemplateResolver *auth.RoleTemplateResolver, sar authorizationv1.SubjectAccessReviewInterface,
) *Validator {
	return &Validator{
		resolver:             resolver,
		roleTemplateResolver: roleTemplateResolver,
		sar:                  sar,
	}
}

// Validator for validating roleTemplates.
type Validator struct {
	resolver             rbacvalidation.AuthorizationRuleResolver
	roleTemplateResolver *auth.RoleTemplateResolver
	sar                  authorizationv1.SubjectAccessReviewInterface
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return roleTemplateGVR
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create, admissionregistrationv1.Delete}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.ValidatingWebhook {
	return admission.NewDefaultValidationWebhook(v, clientConfig, admissionregistrationv1.ClusterScope)
}

// Admit handles the webhook admission request sent to this webhook.
// If this function is called without NewValidator(..) calls will panic.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("Validator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	if request.UserInfo.Username == "system:serviceaccount:cattle-system:rancher-webhook" {
		return nil, fmt.Errorf("GET OUT PLEASE")
	}
	oldRT, newRT, err := objectsv3.RoleTemplateOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get RoleTemplate from request: %w", err)
	}

	fldPath := field.NewPath("roletemplate")
	var fieldErr *field.Error

	switch request.Operation {
	case admissionv1.Update:
		if newRT.DeletionTimestamp != nil {
			// Object is in the process of being deleted, so admit it.
			// This admits update operations that happen to remove finalizers.
			// This is needed to supported the deletion of old RoleTemplates that would not pass the update check that verifies all rules have verbs.
			return &admissionv1.AdmissionResponse{
				Allowed: true,
			}, nil
		}
		fieldErr = v.validateUpdateFields(oldRT, newRT, fldPath, request)
	case admissionv1.Create:
		fieldErr = validateCreateFields(newRT, fldPath)
	case admissionv1.Delete:
		return v.handleDelete(oldRT)
	default:
		return nil, fmt.Errorf("roleTemplate operation %v: %w", request.Operation, admission.ErrUnsupportedOperation)
	}
	if fieldErr != nil {
		return admission.BadRequest(fieldErr.Error()), nil
	}

	// check for circular references produced by this role.
	circularTemplate, err := v.checkCircularRef(newRT)
	if err != nil {
		logrus.Errorf("Error when trying to check for a circular ref: %s", err)
		return nil, err
	}
	if circularTemplate != nil {
		return admission.BadRequest(fmt.Sprintf("Circular Reference: RoleTemplate %s already inherits RoleTemplate %s", circularTemplate.Name, newRT.Name)), nil
	}

	rules, err := v.roleTemplateResolver.RulesFromTemplate(newRT)
	if err != nil {
		return nil, fmt.Errorf("failed to get all rules for '%s': %w", newRT.Name, err)
	}

	allowed, err := auth.EscalationAuthorized(request, roleTemplateGVR, v.sar, "")
	if err != nil {
		logrus.Warnf("Failed to check for the 'escalate' verb on RoleTemplates: %v", err)
	} else if allowed {
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	err = auth.ConfirmNoEscalation(request, rules, "", v.resolver)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Status:  "Failure",
				Message: err.Error(),
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusUnprocessableEntity,
			},
		}, nil
	}

	return &admissionv1.AdmissionResponse{Allowed: true}, nil
}

// validUpdateFields checks if the fields being changed are valid update fields.
func (v *Validator) validateUpdateFields(oldRole, newRole *v3.RoleTemplate, fldPath *field.Path, request *admission.Request) *field.Error {
	if oldRole.Context != newRole.Context {
		return field.Forbidden(fldPath.Child("context"), "")
	}

	if err := validateContextValue(newRole, fldPath); err != nil {
		return err
	}

	if fldError := validation.CheckForVerbs(newRole.Rules, fldPath); fldError != nil {
		return fldError
	}

	if !oldRole.Builtin {
		return nil
	}

	// allow changes to meta data and defaults
	oldRole.ClusterCreatorDefault = newRole.ClusterCreatorDefault
	oldRole.ProjectCreatorDefault = newRole.ProjectCreatorDefault
	oldRole.ObjectMeta = newRole.ObjectMeta

	if !equality.Semantic.DeepEqual(oldRole, newRole) {
		return field.Forbidden(fldPath, "updates to builtIn RoleTemplates for fields other than CreatorDefault are forbidden")
	}
	return nil
}

// validateCreateFields checks if all required fields are present and valid.
func validateCreateFields(newRole *v3.RoleTemplate, fldPath *field.Path) *field.Error {
	if newRole.DisplayName == "" {
		return field.Required(fldPath.Child("displayName"), "")
	}

	if err := validateContextValue(newRole, fldPath); err != nil {
		return err
	}

	return validation.CheckForVerbs(newRole.Rules, fldPath)
}

func validateContextValue(newRole *v3.RoleTemplate, fldPath *field.Path) *field.Error {
	if newRole.Administrative && newRole.Context != clusterContext {
		return field.Forbidden(fldPath.Child("administrative"), "only cluster roles can be administrative")
	}
	if newRole.Context != clusterContext && newRole.Context != projectContext {
		return field.NotSupported(fldPath.Child("context"), newRole.Context, []string{clusterContext, projectContext})
	}
	return nil
}

func (v *Validator) handleDelete(oldRT *v3.RoleTemplate) (*admissionv1.AdmissionResponse, error) {
	allRTs, err := v.roleTemplateResolver.RoleTemplateCache().List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list all RoleTemplates: %w", err)
	}

	// verify that the role is not currently inherited
	for _, roleTemplate := range allRTs {
		for _, templateName := range roleTemplate.RoleTemplateNames {
			if oldRT.Name == templateName {
				return admission.BadRequest(fmt.Sprintf("roletemplate '%s' cannot be deleted because it is inherited by roletemplate '%s'", oldRT.Name, roleTemplate.Name)), nil
			}
		}
	}

	return &admissionv1.AdmissionResponse{Allowed: true}, nil
}

// checkCircularRef looks for a circular ref between this role template and any role template that it inherits
// for example - template 1 inherits template 2 which inherits template 1. These setups can cause high cpu usage/crashes
// If a circular ref was found, returns the first template which inherits this role template. Returns nil otherwise.
// Can return an error if any role template was not found.
func (v *Validator) checkCircularRef(template *v3.RoleTemplate) (*v3.RoleTemplate, error) {
	seen := make(map[string]struct{})
	queue := []*v3.RoleTemplate{template}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, inherited := range current.RoleTemplateNames {
			// if we found a circular reference, exit here and go no further
			if inherited == template.Name {
				// we only look for circular references to this role. We don't check for circular dependencies which
				// don't have this role as one of the targets. Those should have been taken care of when they were originally made
				return current, nil
			}
			// if we haven't seen this yet, we add to the queue to process
			if _, ok := seen[inherited]; !ok {
				newTemplate, err := v.roleTemplateResolver.RoleTemplateCache().Get(inherited)
				if err != nil {
					return nil, fmt.Errorf("unable to get roletemplate %s with error %w", inherited, err)
				}
				seen[inherited] = struct{}{}
				queue = append(queue, newTemplate)
			}
		}
	}
	return nil, nil
}
