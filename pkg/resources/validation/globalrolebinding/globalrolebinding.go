// Package globalrolebinding handles operation validation for globalrolebinding.
package globalrolebinding

import (
	"fmt"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	rbacvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "globalrolebindings",
}

// NewValidator returns a new validator for GlobalRoleBindings.
func NewValidator(grCache v3.GlobalRoleCache, resolver rbacvalidation.AuthorizationRuleResolver) *Validator {
	return &Validator{
		resolver:    resolver,
		globalRoles: grCache,
	}
}

// Validator is used to validate operations to GlobalRoleBindings.
type Validator struct {
	resolver    rbacvalidation.AuthorizationRuleResolver
	globalRoles v3.GlobalRoleCache
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update, admissionregistrationv1.Delete}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.ValidatingWebhook {
	return admission.NewDefaultValidationWebhook(v, clientConfig, admissionregistrationv1.ClusterScope)
}

// Admit handles the webhook admission request sent to this webhook.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("GlobalRoleBinding Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldGRB, newGRB, err := objectsv3.GlobalRoleBindingOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s from request: %w", gvr.Resource, err)
	}

	fldPath := field.NewPath(gvr.Resource)
	var fieldErr *field.Error

	switch request.Operation {
	case admissionv1.Update:
		fieldErr = validateUpdateFields(oldGRB, newGRB, fldPath)
	case admissionv1.Create:
		fieldErr = validateCreateFields(newGRB, fldPath)
	case admissionv1.Delete:
		// do nothing
	default:
		return nil, fmt.Errorf("%s operation %v: %w", gvr.Resource, request.Operation, admission.ErrUnsupportedOperation)
	}

	if fieldErr != nil {
		return admission.BadRequest(fieldErr.Error()), nil
	}
	return v.checkForEscalation(newGRB, request)
}

// validUpdateFields checks if the fields being changed are valid update fields.
func validateUpdateFields(oldBinding, newBinding *apisv3.GlobalRoleBinding, fldPath *field.Path) *field.Error {
	var err *field.Error
	switch {
	case newBinding.UserName != oldBinding.UserName:
		err = field.Forbidden(fldPath.Child("userName"), "can not update")
	case newBinding.GroupPrincipalName != oldBinding.GroupPrincipalName:
		err = field.Forbidden(fldPath.Child("groupPrincipalName"), "can not update")
	case newBinding.GlobalRoleName != oldBinding.GlobalRoleName:
		err = field.Forbidden(fldPath.Child("globalRoleName"), "can not update")
	}

	return err
}

// validateCreateFields checks if all required fields are present and valid.
func validateCreateFields(newBinding *apisv3.GlobalRoleBinding, fldPath *field.Path) *field.Error {
	var err *field.Error
	switch {
	case newBinding.UserName != "" && newBinding.GroupPrincipalName != "":
		err = field.Forbidden(fldPath, "bindings can not set both userName and groupPrincipalName")
	case newBinding.UserName == "" && newBinding.GroupPrincipalName == "":
		err = field.Required(fldPath, "bindings must have either userName or groupPrincipalName set")
	}

	return err
}

// checkForEscalation checks if the rules being given in the GlobalRoleBinding are a subset of rules held by the user issuing the request.
func (v *Validator) checkForEscalation(newGRB *apisv3.GlobalRoleBinding, request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	response := &admissionv1.AdmissionResponse{}

	// Get global role for escalation check
	globalRole, err := v.globalRoles.Get(newGRB.GlobalRoleName)
	if err == nil {
		auth.SetEscalationResponse(response, auth.ConfirmNoEscalation(request, globalRole.Rules, "", v.resolver))
		return response, nil
	}

	if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get globalrole: %w", err)
	}

	switch {
	case request.Operation == admissionv1.Delete:
		// allow delete operations if the GR is not found
		response.Allowed = true
	case request.Operation == admissionv1.Update && newGRB.DeletionTimestamp != nil:
		// only allow updates to the finalizers if the GR is not found
		response.Allowed = true
	default:
		fieldErr := field.NotFound(field.NewPath("globalrolebinding", "globalRoleName"), newGRB.Name)
		response = admission.BadRequest(fieldErr.Error())
	}
	return response, nil
}
