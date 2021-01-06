package capabilities

import (
	"fmt"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	"strings"

	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/internal/override"
	"github.com/majeinfo/kubesecaudit/k8stypes"
)

const Name = "capabilities"

// DefaultDropList is the list of capabilities that will be dropped if no drop list is specified
// https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities
var DefaultDropList = []string{
	"AUDIT_WRITE",      // Write records to kernel auditing log
	"CHOWN",            // Make arbitrary changes to file UIDs and GIDs (see chown(2))
	"DAC_OVERRIDE",     // Bypass file read, write, and execute permission checks
	"FOWNER",           // Bypass permission checks on operations that normally require the file system UID of the process to match the UID of the file
	"FSETID",           // Don’t clear set-user-ID and set-group-ID permission bits when a file is modified
	"KILL",             // Bypass permission checks for sending signals
	"MKNOD",            // Create special files using mknod(2)
	"NET_BIND_SERVICE", // Bind a socket to internet domain privileged ports (port numbers less than 1024)
	"NET_RAW",          // Use RAW and PACKET sockets
	"SETFCAP",          // Set file capabilities
	"SETGID",           // Make arbitrary manipulations of process GIDs and supplementary GID list
	"SETPCAP",          // Modify process capabilities.
	"SETUID",           // Make arbitrary manipulations of process UIDs
	"SYS_CHROOT",       // Use chroot(2), change root directory
}

const (
	// CapabilityAdded occurs when a capability is in the capability add list of a container's security context
	CapabilityAdded = "CapabilityAdded"
	// CapabilityNotDropped occurs when a capability that should be dropped is not in the capability drop list of a container's security context
	CapabilityNotDropped = "CapabilityNotDropped"
)

const overrideLabelPrefix = "allow-capability-"

// Capabilities implements Auditable
type Capabilities struct {
	dropList []string
}

func New(config Config) *Capabilities {
	return &Capabilities{
		dropList: config.GetDropList(),
	}
}

// Audit checks that bad capabilities are dropped and no capabilities are added
func (a *Capabilities) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	for _, resource := range resources {
		if !k8stypes.IsPodV1(resource) {
			continue
		}

		for _, container := range k8s.GetContainers(resource) {
			// Generate a single message per container (one msg for addedCap and one for notDroppedCap)
			var addedCap, notDroppedCap []string

			for _, cap := range mergeCapabilities(a.dropList, container) {
				auditResult := auditCapabilityIsAdded(container, cap, a.dropList, resource)
				auditResult = override.ApplyOverride(auditResult, container.Name, resource, getOverrideLabel(cap))
				if auditResult != nil {
					//auditResults = append(auditResults, auditResult)
					addedCap = append(addedCap, cap)
				}
				auditResult = auditCapabilityIsNotDropped(container, cap, a.dropList, resource)
				auditResult = override.ApplyOverride(auditResult, container.Name, resource, getOverrideLabel(cap))
				if auditResult != nil {
					//auditResults = append(auditResults, auditResult)
					notDroppedCap = append(notDroppedCap, cap)
				}
			}

			if len(addedCap) > 0 {
				auditResult := &audit.AuditResult{
					Name:     CapabilityAdded,
					Severity: audit.Error,
					Message:  fmt.Sprintf("Capability added. It should be removed from the capability add list. If you need this capability, add an override label such as '%s: SomeReason'.",
						override.GetContainerOverrideLabel(container.Name, getOverrideLabel(addedCap[0]))),
					PendingFix: &fixCapabilityAdded{
						container:  container,
						capability: strings.Join(addedCap, ", "),
					},
					Resource: resource,
					Metadata: audit.Metadata{
						"Container":  container.Name,
						"Capability": strings.Join(addedCap, ", "),
					},
				}
				auditResults = append(auditResults, auditResult)
			}
			if len(notDroppedCap) > 0 {
				auditResult := &audit.AuditResult{
					Name:     CapabilityNotDropped,
					Severity: audit.Error,
					Message:  "Capability not dropped. Ideally, the capability drop list should include the single capability 'ALL' which drops all capabilities.",
					PendingFix: &fixCapabilityNotDropped{
						container:  container,
						capability: strings.Join(notDroppedCap, ", "),
					},
					Resource: resource,
					Metadata: audit.Metadata{
						"Container":  container.Name,
						"Capability": strings.Join(notDroppedCap, ", "),
					},
				}
				auditResults = append(auditResults, auditResult)
			}
		}
	}

	return auditResults, nil
}

func getOverrideLabel(capability string) string {
	return overrideLabelPrefix + strings.Replace(strings.ToLower(capability), "_", "-", -1)
}

func auditCapabilityIsAdded(container *k8stypes.ContainerV1, capability string, dropList []string, resource k8stypes.Resource) *audit.AuditResult {
	if isCapabilityAdded(container, capability) {
		auditResult := &audit.AuditResult{
			Name:     CapabilityAdded,
			Severity: audit.Error,
			Message:  fmt.Sprintf("Capability added. It should be removed from the capability add list. If you need this capability, add an override label such as '%s: SomeReason'.", override.GetContainerOverrideLabel(container.Name, getOverrideLabel(capability))),
			PendingFix: &fixCapabilityAdded{
				container:  container,
				capability: capability,
			},
			Resource: resource,
			Metadata: audit.Metadata{
				"Container":  container.Name,
				"Capability": capability,
			},
		}
		return auditResult
	}

	return nil
}

func auditCapabilityIsNotDropped(container *k8stypes.ContainerV1, capability string, dropList []string, resource k8stypes.Resource) *audit.AuditResult {
	if isCapabilityNotDropped(container, capability, dropList) {
		auditResult := &audit.AuditResult{
			Name:     CapabilityNotDropped,
			Severity: audit.Error,
			Message:  "Capability not dropped. Ideally, the capability drop list should include the single capability 'ALL' which drops all capabilities.",
			PendingFix: &fixCapabilityNotDropped{
				container:  container,
				capability: capability,
			},
			Resource: resource,
			Metadata: audit.Metadata{
				"Container":  container.Name,
				"Capability": capability,
			},
		}
		return auditResult
	}

	return nil
}

func auditContainerForCapability(container *k8stypes.ContainerV1, capability string, dropList []string, resource k8stypes.Resource) (auditResults []*audit.AuditResult) {
	if isCapabilityAdded(container, capability) {
		auditResult := &audit.AuditResult{
			Name:     CapabilityAdded,
			Severity: audit.Error,
			Message:  fmt.Sprintf("Capability added. It should be removed from the capability add list. If you need this capability, add an override label such as '%s: SomeReason'.", override.GetContainerOverrideLabel(container.Name, getOverrideLabel(capability))),
			PendingFix: &fixCapabilityAdded{
				container:  container,
				capability: capability,
			},
			Resource: resource,
			Metadata: audit.Metadata{
				"Container":  container.Name,
				"Capability": capability,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if isCapabilityNotDropped(container, capability, dropList) {
		auditResult := &audit.AuditResult{
			Name:     CapabilityNotDropped,
			Severity: audit.Error,
			Message:  "Capability not dropped. Ideally, the capability drop list should include the single capability 'ALL' which drops all capabilities.",
			PendingFix: &fixCapabilityNotDropped{
				container:  container,
				capability: capability,
			},
			Resource: resource,
			Metadata: audit.Metadata{
				"Container":  container.Name,
				"Capability": capability,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	// We need the audit result to be nil for ApplyOverride to check for RedundantAuditorOverride errors
	if len(auditResults) == 0 {
		return []*audit.AuditResult{nil}
	}

	return
}

