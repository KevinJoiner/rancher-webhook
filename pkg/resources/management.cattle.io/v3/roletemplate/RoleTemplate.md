## Validation Checks

Note: all checks are bypassed if the RoleTemplate is being deleted

###  Circular Reference

Circular references to webhooks (a inherits b, b inherits a) are not allowed. More specifically, if "roleTemplate1" is included in the `roleTemplateNames` of "roleTemplate2", then "roleTemplate2" must not be included in the `roleTemplateNames` of "roleTemplate1". This checks prevents the creation of roles whose end-state cannot be resolved.

### Rules Without Verbs 

Rules without verbs are not permitted. The `rules` included in a roleTemplate are of the same type as the rules used by standard kubernetes RBAC types (such as `Roles` from `rbac.authorization.k8s.io/v1`). Because of this, they inherit the same restrictions as these types, including this one.

### Escalation Prevention

Users can only change RoleTemplates with rights less than or equal to those they currently possess. This prevents privilege escalation. 

