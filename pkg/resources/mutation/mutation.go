package mutation

import (
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetCreatorIDAnnotation sets the creatorID Annotation on the newObj based  on the user specified in the request.
func SetCreatorIDAnnotation(request *admission.Request, newObj metav1.Object) error {
	annotations := newObj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[auth.CreatorIDAnn] = request.UserInfo.Username
	newObj.SetAnnotations(annotations)
	// if err := patch.CreatePatch(obj.Raw, newObj, response); err != nil {
	// 	return fmt.Errorf("failed to create patch: %w", err)
	// }
	return nil
}
