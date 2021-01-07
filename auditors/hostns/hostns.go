package hostns

import (
	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	"github.com/majeinfo/kubesecaudit/internal/override"
	"github.com/majeinfo/kubesecaudit/k8stypes"
)

const Name = "hostns"

const (
	// NamespaceHostNetworkTrue occurs when hostNetwork is set to true in the container podspec
	NamespaceHostNetworkTrue = "NamespaceHostNetworkTrue"
	// NamespaceHostIPCTrue occurs when hostIPC is set to true in the container podspec
	NamespaceHostIPCTrue = "NamespaceHostIPCTrue"
	// NamespaceHostPIDTrue occurs when hostPID is set to true in the container podspec
	NamespaceHostPIDTrue = "NamespaceHostPIDTrue"
)

// HostNamespaces implements Auditable
type HostNamespaces struct{}

func New() *HostNamespaces {
	return &HostNamespaces{}
}

const HostNetworkOverrideLabel = "allow-namespace-host-network"
const HostIPCOverrideLabel = "allow-namespace-host-IPC"
const HostPIDOverrideLabel = "allow-namespace-host-PID"

// Audit checks that hostNetwork, hostIPC and hostPID are set to false in container podSpecs
func (a *HostNamespaces) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	for _, resource := range resources {
		podSpec := k8s.GetPodSpec(resource)
		if podSpec == nil {
			return nil, nil
		}

		for _, check := range []struct {
			auditFunc     func(*k8stypes.PodSpecV1) *audit.AuditResult
			overrideLabel string
		}{
			{auditHostNetwork, HostNetworkOverrideLabel},
			{auditHostIPC, HostIPCOverrideLabel},
			{auditHostPID, HostPIDOverrideLabel},
		} {
			auditResult := check.auditFunc(podSpec)
			auditResult = override.ApplyOverride(auditResult, "", resource, check.overrideLabel)
			if auditResult != nil {
				auditResults = append(auditResults, auditResult)
			}
		}
	}

	return auditResults, nil
}

func auditHostNetwork(podSpec *k8stypes.PodSpecV1) *audit.AuditResult {
	if podSpec.HostNetwork {
		metadata := audit.Metadata{}
		if podSpec.Hostname != "" {
			metadata["PodHost"] = podSpec.Hostname
		}
		return &audit.AuditResult{
			Name:     NamespaceHostNetworkTrue,
			Severity: audit.Error,
			Message:  "hostNetwork is set to 'true' in PodSpec. It should be set to 'false'.",
			PendingFix: &fixHostNetworkTrue{
				podSpec: podSpec,
			},
			Metadata: metadata,
		}
	}

	return nil
}

func auditHostIPC(podSpec *k8stypes.PodSpecV1) *audit.AuditResult {
	if podSpec.HostIPC {
		metadata := audit.Metadata{}
		if podSpec.Hostname != "" {
			metadata["PodHost"] = podSpec.Hostname
		}
		return &audit.AuditResult{
			Name:     NamespaceHostIPCTrue,
			Severity: audit.Error,
			Message:  "hostIPC is set to 'true' in PodSpec. It should be set to 'false'.",
			PendingFix: &fixHostIPCTrue{
				podSpec: podSpec,
			},
			Metadata: metadata,
		}
	}

	return nil
}

func auditHostPID(podSpec *k8stypes.PodSpecV1) *audit.AuditResult {
	if podSpec.HostPID {
		metadata := audit.Metadata{}
		if podSpec.Hostname != "" {
			metadata["PodHost"] = podSpec.Hostname
		}
		return &audit.AuditResult{
			Name:     NamespaceHostPIDTrue,
			Severity: audit.Error,
			Message:  "hostPID is set to 'true' in PodSpec. It should be set to 'false'.",
			PendingFix: &fixHostPIDTrue{
				podSpec: podSpec,
			},
			Metadata: metadata,
		}
	}

	return nil
}

