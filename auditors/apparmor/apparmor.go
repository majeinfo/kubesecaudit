package apparmor

import (
	"fmt"
	"strings"

	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/internal/fix"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	"github.com/majeinfo/kubesecaudit/k8stypes"
)

const Name = "apparmor"

const (
	// AppArmorAnnotationMissing occurs when the apparmor annotation is missing
	AppArmorAnnotationMissing = "AppArmorAnnotationMissing"
	// AppArmorDisabled occurs when the apparmor annotation is set to a bad value
	AppArmorDisabled = "AppArmorDisabled"
	// AppArmorInvalidAnnotation occurs when the apparmor annotation key refers to a container which doesn't exist. This will
	// prevent the manifest from being applied to a cluster with AppArmor enabled.
	AppArmorInvalidAnnotation = "AppArmorInvalidAnnotation"
)

// As of Jan 14, 2020 these constants are not in the K8s API package, but once they are they should be replaced
// https://github.com/kubernetes/kubernetes/blob/master/pkg/security/apparmor/helpers.go#L25
const (
	// The prefix to an annotation key specifying a container profile.
	ContainerAnnotationKeyPrefix = "container.apparmor.security.beta.kubernetes.io/"

	// The profile specifying the runtime default.
	ProfileRuntimeDefault = "runtime/default"
	// The prefix for specifying profiles loaded on the node.
	ProfileNamePrefix = "localhost/"
)

// AppArmor implements Auditable
type AppArmor struct{}

func New() *AppArmor {
	return &AppArmor{}
}

// Audit checks that AppArmor is enabled for all containers
func (a *AppArmor) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult
	var containerNames []string

	for _, resource := range resources {
		for _, container := range k8s.GetContainers(resource) {
			containerNames = append(containerNames, container.Name)
			auditResult := auditContainer(container, resource)
			if auditResult != nil {
				auditResults = append(auditResults, auditResult)
			}
		}

		auditResults = append(auditResults, auditPodAnnotations(resource, containerNames)...)
	}

	return auditResults, nil
}

func auditContainer(container *k8stypes.ContainerV1, resource k8stypes.Resource) *audit.AuditResult {
	annotations := k8s.GetAnnotations(resource)
	containerAnnotation := getContainerAnnotation(container)

	if isAppArmorAnnotationMissing(containerAnnotation, annotations) {
		return &audit.AuditResult{
			Name:     AppArmorAnnotationMissing,
			Severity: audit.Error,
			Message:  fmt.Sprintf("AppArmor annotation missing. The annotation '%s' should be added.", containerAnnotation),
			Metadata: audit.Metadata{
				"Container":         container.Name,
				"MissingAnnotation": containerAnnotation,
			},
			PendingFix: &fix.ByAddingPodAnnotation{
				Key:   containerAnnotation,
				Value: ProfileRuntimeDefault,
			},
		}
	}

	if isAppArmorDisabled(containerAnnotation, annotations) {
		return &audit.AuditResult{
			Name:     AppArmorDisabled,
			Message:  fmt.Sprintf("AppArmor is disabled. The apparmor annotation should be set to '%s' or start with '%s'.", ProfileRuntimeDefault, ProfileNamePrefix),
			Severity: audit.Error,
			Metadata: audit.Metadata{
				"Container":       container.Name,
				"Annotation":      containerAnnotation,
				"AnnotationValue": getProfileName(containerAnnotation, annotations),
			},
			PendingFix: &fix.BySettingPodAnnotation{
				Key:   containerAnnotation,
				Value: ProfileRuntimeDefault,
			},
		}
	}

	return nil
}

func auditPodAnnotations(resource k8stypes.Resource, containerNames []string) []*audit.AuditResult {
	var auditResults []*audit.AuditResult
	for annotationKey, annotationValue := range k8s.GetAnnotations(resource) {
		if !strings.HasPrefix(annotationKey, ContainerAnnotationKeyPrefix) {
			continue
		}
		containerName := strings.Split(annotationKey, "/")[1]
		if !contains(containerNames, containerName) {
			auditResults = append(auditResults, &audit.AuditResult{
				Name:     AppArmorInvalidAnnotation,
				Severity: audit.Error,
				Message:  fmt.Sprintf("AppArmor annotation key refers to a container that doesn't exist. Remove the annotation '%s: %s'.", annotationKey, annotationValue),
				Metadata: audit.Metadata{
					"Container":  containerName,
					"Annotation": fmt.Sprintf("%s: %s", annotationKey, annotationValue),
				},
				PendingFix: &fix.ByRemovingPodAnnotation{
					Key: annotationKey,
				},
			})
		}
	}
	return auditResults
}

func isAppArmorAnnotationMissing(apparmorAnnotation string, annotations map[string]string) bool {
	_, ok := annotations[apparmorAnnotation]
	return !ok
}

func isAppArmorDisabled(apparmorAnnotation string, annotations map[string]string) bool {
	profileName, ok := annotations[apparmorAnnotation]
	return !ok || profileName != ProfileRuntimeDefault && !strings.HasPrefix(profileName, ProfileNamePrefix)
}

func getContainerAnnotation(container *k8stypes.ContainerV1) string {
	return ContainerAnnotationKeyPrefix + container.Name
}

func getProfileName(apparmorAnnotation string, annotations map[string]string) string {
	profileName := annotations[apparmorAnnotation]
	return profileName
}

func contains(arr []string, val string) bool {
	for _, arrVal := range arr {
		if arrVal == val {
			return true
		}
	}
	return false
}

