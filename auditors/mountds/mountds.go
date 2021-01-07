package mountds

import (
	"fmt"

	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	"github.com/majeinfo/kubesecaudit/k8stypes"
)

const Name = "mountds"

const (
	// TODO: what about containerd socket ?
	// DockerSocketMounted occurs when a container has Docker socket mounted
	DockerSocketMounted = "DockerSocketMounted"
)

// DockerSocketPath is the mount path of the Docker socket
const DockerSocketPath = "/var/run/docker.sock"

// DockerSockMounted implements Auditable
type DockerSockMounted struct{}

func New() *DockerSockMounted {
	return &DockerSockMounted{}
}

// Audit checks that the container does not have the Docker socket mounted
func (limits *DockerSockMounted) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	for _, resource := range resources {
		for _, container := range k8s.GetContainers(resource) {
			auditResult := auditContainer(container)
			if auditResult != nil {
				auditResults = append(auditResults, auditResult)
			}
		}
	}

	return auditResults, nil
}

func auditContainer(container *k8stypes.ContainerV1) *audit.AuditResult {
	if isDockerSocketMounted(container) {
		return &audit.AuditResult{
			Name:     DockerSocketMounted,
			Severity: audit.Warn,
			Message:  fmt.Sprintf("Docker socket is mounted. '%s' should be removed from the container's volume mount list.", DockerSocketPath),
			Metadata: audit.Metadata{
				"Container": container.Name,
			},
		}
	}

	return nil
}

func isDockerSocketMounted(container *k8stypes.ContainerV1) bool {
	if container.VolumeMounts == nil {
		return false
	}

	for _, mount := range container.VolumeMounts {
		if mount.MountPath == DockerSocketPath {
			return true
		}
	}

	return false
}

