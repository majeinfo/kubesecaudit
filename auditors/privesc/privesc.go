package privesc

import (
	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	"github.com/majeinfo/kubesecaudit/internal/override"
	"github.com/majeinfo/kubesecaudit/k8stypes"
)

const Name = "privesc"

const (
	// AllowPrivilegeEscalationNil occurs when the AllowPrivilegeEscalation field is missing or unset in the
	// container SecurityContext
	AllowPrivilegeEscalationNil = "AllowPrivilegeEscalationNil"
	// AllowPrivilegeEscalationTrue occurs when the AllowPrivilegeEscalation field is set to true in the container
	// security context
	AllowPrivilegeEscalationTrue = "AllowPrivilegeEscalationTrue"
)

const OverrideLabel = "allow-privilege-escalation"

// AllowPrivilegeEscalation implements Auditable
type AllowPrivilegeEscalation struct{}

func New() *AllowPrivilegeEscalation {
	return &AllowPrivilegeEscalation{}
}

// Audit checks that AllowPrivilegeEscalation is disabled (set to false) in the container SecurityContext
func (a *AllowPrivilegeEscalation) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	for _, resource := range resources {
		for _, container := range k8s.GetContainers(resource) {
			auditResult := auditContainer(container)
			auditResult = override.ApplyOverride(auditResult, container.Name, resource, OverrideLabel)
			if auditResult != nil {
				auditResults = append(auditResults, auditResult)
			}
		}
	}

	return auditResults, nil
}

func auditContainer(container *k8stypes.ContainerV1) *audit.AuditResult {
	if isAllowPrivilegeEscalationNil(container) {
		return &audit.AuditResult{
			Name:     AllowPrivilegeEscalationNil,
			Severity: audit.Error,
			Message:  "allowPrivilegeEscalation not set which allows privilege escalation. It should be set to 'false'.",
			PendingFix: &fixBySettingAllowPrivilegeEscalationFalse{
				container: container,
			},
			Metadata: audit.Metadata{
				"Container": container.Name,
			},
		}
	}

	if isAllowPrivilegeEscalationTrue(container) {
		return &audit.AuditResult{
			Name:     AllowPrivilegeEscalationTrue,
			Severity: audit.Error,
			Message:  "allowPrivilegeEscalation set to 'true'. It should be set to 'false'.",
			PendingFix: &fixBySettingAllowPrivilegeEscalationFalse{
				container: container,
			},
			Metadata: audit.Metadata{
				"Container": container.Name,
			},
		}
	}

	return nil
}

func isAllowPrivilegeEscalationNil(container *k8stypes.ContainerV1) bool {
	return container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil
}

func isAllowPrivilegeEscalationTrue(container *k8stypes.ContainerV1) bool {
	return container.SecurityContext != nil && *container.SecurityContext.AllowPrivilegeEscalation
}

