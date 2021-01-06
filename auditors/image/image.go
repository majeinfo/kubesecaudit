package image

import (
	"fmt"
	"strings"

	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	"github.com/majeinfo/kubesecaudit/k8stypes"
)

const Name = "image"

const (
	// ImageTagMissing occurs when the container image tag is missing
	ImageTagMissing   = "ImageTagMissing"
	// ImageTagIncorrect occurs when the container image tag does not match the user-provided value
	ImageTagIncorrect = "ImageTagIncorrect"
	// ImageCorrect occurs when the container image tag is correct
	ImageCorrect      = "ImageCorrect"
)

// Image implements Auditable
type Image struct {
	image string
}

func New(config Config) *Image {
	return &Image{
		image: config.GetImage(),
	}
}

// Audit checks that the container image matches the provided image
func (image *Image) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	for _, resource := range resources {
		if !k8stypes.IsPodV1(resource) {
			continue
		}

		for _, container := range k8s.GetContainers(resource) {
			auditResult := auditContainer(container, image.image, resource)
			if auditResult != nil {
				auditResults = append(auditResults, auditResult)
			}
		}
	}

	return auditResults, nil
}

func auditContainer(container *k8stypes.ContainerV1, image string, resource k8stypes.Resource) *audit.AuditResult {
	name, tag := splitImageString(image)
	containerName, containerTag := splitImageString(container.Image)

	if isImageTagMissing(containerTag) {
		return &audit.AuditResult{
			Name:     ImageTagMissing,
			Severity: audit.Warn,
			Message:  "Image tag is missing.",
			Resource: &resource,
			Metadata: audit.Metadata{
				"Container": container.Name,
			},
		}
	}

	if isImageTagIncorrect(name, tag, containerName, containerTag) {
		return &audit.AuditResult{
			Name:     ImageTagIncorrect,
			Severity: audit.Error,
			Message:  fmt.Sprintf("Container tag is incorrect. It should be set to '%s'.", tag),
			Resource: &resource,
			Metadata: audit.Metadata{
				"Container": container.Name,
			},
		}
	}

	if isImageCorrect(name, tag, containerName, containerTag) {
		return &audit.AuditResult{
			Name:     ImageCorrect,
			Severity: audit.Info,
			Message:  "Image tag is correct",
			Resource: &resource,
			Metadata: audit.Metadata{
				"Container": container.Name,
			},
		}
	}

	return nil
}

func isImageTagMissing(tag string) bool {
	return len(tag) == 0
}

func isImageTagIncorrect(name, tag, containerName, containerTag string) bool {
	return containerName == name && containerTag != tag
}

func isImageCorrect(name, tag, containerName, containerTag string) bool {
	return containerName == name && containerTag == tag
}

func splitImageString(image string) (name, tag string) {
	tokens := strings.Split(image, ":")
	if len(tokens) > 0 {
		name = tokens[0]
	}
	if len(tokens) > 1 {
		tag = tokens[1]
	}
	return
}

