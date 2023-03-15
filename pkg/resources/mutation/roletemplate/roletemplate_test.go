package roletemplate_test

import (
	"context"
	"encoding/json"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/mutation/roletemplate"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestMutator_Admit(t *testing.T) {
	mutator := &roletemplate.Mutator{}
	roleTemplate := &v3.RoleTemplate{
		TypeMeta: metav1.TypeMeta{Kind: "RoleTemplate", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rt-new",
			Namespace: "c-namespace",
		},
	}
	req := createRTRequest(t, roleTemplate, "admin")
	resp, err := mutator.Admit(req)
	if assert.NoError(t, err, "unexpected error from admit") {
		assert.Truef(t, resp.Allowed, "Response was incorrectly denied")
	}

	req.Object = runtime.RawExtension{}
	_, err = mutator.Admit(req)
	assert.Error(t, err, "Admit should fail on bad request object")
}

// createRTRequest will return a new webhookRequest with the using the given RTs
// if oldRT is nil then a request will be returned as a create operation.
// if newRT is nil then a request will be returned as a delete operation.
// else the request will look like and update operation.
func createRTRequest(t *testing.T, newRT *v3.RoleTemplate, username string) *admission.Request {
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
	req.Name = newRT.Name
	req.Namespace = newRT.Namespace
	req.Object.Raw, err = json.Marshal(newRT)
	assert.NoError(t, err, "Failed to marshal RT while creating request")

	return req
}
