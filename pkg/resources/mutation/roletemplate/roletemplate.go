// Package roletemplate handles the validation of request made to roletemplates.management.cattle.io.
package roletemplate

import (
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/patch"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

const (
	cleanupKey = "cleanup.cattle.io/rtUpgradeCluster"
)

var roleTemplateGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "roletemplates",
}

// Mutator for mutating roleTemplates.
type Mutator struct{}

// GVR returns the GroupVersionKind for this CRD.
func (m *Mutator) GVR() schema.GroupVersionResource {
	return roleTemplateGVR
}

// Operations returns list of operations handled by this mutator.
func (m *Mutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.MutatingWebhook {
	return admission.NewDefaultMutationWebhook(m, clientConfig, admissionregistrationv1.ClusterScope)
}

// Admit handles the webhook admission request sent to this webhook.
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("RoleTemple Mutator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	newRT, err := objectsv3.RoleTemplateFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get RoleTemplate from request: %w", err)
	}
	if newRT.Annotations == nil {
		newRT.Annotations = map[string]string{}
	}
	newRT.Annotations[cleanupKey] = "true"
	response := &admissionv1.AdmissionResponse{}
	if err := patch.CreatePatch(request.Object.Raw, newRT, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}
