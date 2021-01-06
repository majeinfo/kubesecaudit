package limits

import (
	"fmt"

	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	"github.com/majeinfo/kubesecaudit/k8stypes"
	v1 "k8s.io/api/core/v1"
	k8sResource "k8s.io/apimachinery/pkg/api/resource"
)

const Name = "limits"

const (
	// LimitsNotSet occurs when there are no cpu and memory limits specified for a container
	LimitsNotSet = "LimitsNotSet"
	// LimitsCPUNotSet occurs when there is no cpu limit specified for a container
	LimitsCPUNotSet = "LimitsCPUNotSet"
	// LimitsMemoryNotSet occurs when there is no memory limit specified for a container
	LimitsMemoryNotSet = "LimitsMemoryNotSet"
	// LimitsCPUExceeded occurs when the CPU limit specified for a container is higher than the specified max CPU limit
	LimitsCPUExceeded = "LimitsCPUExceeded"
	// LimitsMemoryExceeded occurs when the memory limit specified for a container is higher than the specified max memory limit
	LimitsMemoryExceeded = "LimitsMemoryExceeded"
)

// Limits implements Auditable
type Limits struct {
	maxCPU    k8sResource.Quantity
	maxMemory k8sResource.Quantity
}

func New(config Config) (*Limits, error) {
	maxCPU, err := config.GetCPU()
	if err != nil {
		return nil, fmt.Errorf("error creating Limits auditor: %w", err)
	}

	maxMemory, err := config.GetMemory()
	if err != nil {
		return nil, fmt.Errorf("error creating Limits auditor: %w", err)
	}

	return &Limits{
		maxCPU:    maxCPU,
		maxMemory: maxMemory,
	}, nil
}

// Audit checks that the container cpu and memory limits do not exceed specified limits
func (limits *Limits) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	for _, resource := range resources {
		if !k8stypes.IsPodV1(resource) {
			continue
		}

		for _, container := range k8s.GetContainers(resource) {
			for _, auditResult := range limits.auditContainer(container, resource) {
				if auditResult != nil {
					auditResults = append(auditResults, auditResult)
				}
			}
		}
	}

	return auditResults, nil
}

func (limits *Limits) auditContainer(container *k8stypes.ContainerV1, resource k8stypes.Resource) (auditResults []*audit.AuditResult) {
	if isLimitsNil(container) {
		auditResult := &audit.AuditResult{
			Name:     LimitsNotSet,
			Severity: audit.Warn,
			Message:  "Resource limits not set.",
			Resource: &resource,
			Metadata: audit.Metadata{
				"Container": container.Name,
			},
		}
		return []*audit.AuditResult{auditResult}
	}

	containerLimits := getLimits(container)
	cpu := containerLimits.Cpu().String()
	memory := containerLimits.Memory().String()

	if isCPULimitUnset(container) {
		auditResult := &audit.AuditResult{
			Name:     LimitsCPUNotSet,
			Severity: audit.Warn,
			Message:  "Resource CPU limit not set.",
			Resource: &resource,
			Metadata: audit.Metadata{
				"Container": container.Name,
			},
		}
		auditResults = append(auditResults, auditResult)
	} else if exceedsCPULimit(container, limits) {
		maxCPU := limits.maxCPU.String()
		auditResult := &audit.AuditResult{
			Name:     LimitsCPUExceeded,
			Severity: audit.Warn,
			Message:  fmt.Sprintf("CPU limit exceeded. It is set to '%s' which exceeds the max CPU limit of '%s'.", cpu, maxCPU),
			Resource: &resource,
			Metadata: audit.Metadata{
				"Container":         container.Name,
				"ContainerCpuLimit": cpu,
				"MaxCPU":            maxCPU,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if isMemoryLimitUnset(container) {
		auditResult := &audit.AuditResult{
			Name:     LimitsMemoryNotSet,
			Severity: audit.Warn,
			Message:  "Resource Memory limit not set.",
			Resource: &resource,
			Metadata: audit.Metadata{
				"Container": container.Name,
			},
		}
		auditResults = append(auditResults, auditResult)
	} else if exceedsMemoryLimit(container, limits) {
		maxMemory := limits.maxMemory.String()
		auditResult := &audit.AuditResult{
			Name:     LimitsMemoryExceeded,
			Severity: audit.Warn,
			Message:  fmt.Sprintf("Memory limit exceeded. It is set to '%s' which exceeds the max Memory limit of '%s'.", memory, maxMemory),
			Resource: &resource,
			Metadata: audit.Metadata{
				"Container":            container.Name,
				"ContainerMemoryLimit": memory,
				"MaxMemory":            maxMemory,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return
}

func exceedsCPULimit(container *k8stypes.ContainerV1, limits *Limits) bool {
	containerLimits := getLimits(container)
	cpuLimit := containerLimits.Cpu().MilliValue()
	maxCPU := limits.maxCPU.MilliValue()
	return maxCPU > 0 && cpuLimit > maxCPU
}

func exceedsMemoryLimit(container *k8stypes.ContainerV1, limits *Limits) bool {
	containerLimits := getLimits(container)
	memoryLimit := containerLimits.Memory().Value()
	maxMemory := limits.maxMemory.Value()
	return maxMemory > 0 && memoryLimit > maxMemory
}

func isLimitsNil(container *k8stypes.ContainerV1) bool {
	return container.Resources.Limits == nil
}

func isCPULimitUnset(container *k8stypes.ContainerV1) bool {
	limits := getLimits(container)
	cpu := limits.Cpu()
	return cpu == nil || cpu.IsZero()
}

func isMemoryLimitUnset(container *k8stypes.ContainerV1) bool {
	limits := getLimits(container)
	memory := limits.Memory()
	return memory == nil || memory.IsZero()
}

func getLimits(container *k8stypes.ContainerV1) v1.ResourceList {
	if isLimitsNil(container) {
		return v1.ResourceList{}
	}

	return container.Resources.Limits
}

