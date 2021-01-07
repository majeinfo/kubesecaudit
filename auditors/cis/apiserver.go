package cis

import (
	"strings"

	"github.com/majeinfo/kubesecaudit/audit"
)

func auditAPIServer(procs []Process) []*audit.AuditResult {
	var auditResults []*audit.AuditResult
	var proc *Process

	if proc = FindProc(procs, proc_apiserver); proc == nil {
		auditResult := &audit.AuditResult{
			Name:     KubeApiServerNotFound,
			Severity: audit.Warn,
			Message:  "Api-server not found - no audit done",
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
		return auditResults
	}

	// Examine the options (set the default values first)
	opt_anonymous_auth := true

	for _, option := range proc.options {
		if option == "--anonymous-auth=false" {
			opt_anonymous_auth = false
			continue
		}
		if strings.HasPrefix(option, "--authorization-mode=") {
			auditResults = append(auditResults, auditAPIServerAuthorizationMode(option)...)
			continue
		}
		if strings.HasPrefix(option, "--enable-admission-plugins=") {
			auditResults = append(auditResults, auditAPIServerEnableAdmissionPlugins(option)...)
			continue
		}
	}

	if findPrefixName(proc.options, "--basic-auth-file=") {
		auditResult := &audit.AuditResult{
			Name:     BasicAuthFileDefined,
			Severity: audit.Error,
			Message:  "Basic authentication file defined - Password lifetime is illimited, changing them needs a restart",
			PendingFix: &fixBasicAuthFileEnabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if findPrefixName(proc.options, "--token-auth-file=") {
		auditResult := &audit.AuditResult{
			Name:     TokenAuthFileDefined,
			Severity: audit.Error,
			Message:  "Token authentication file defined - Tokens are stored in clear text and their lifetime is illimited, changing them needs a restart",
			PendingFix: &fixTokenAuthFileEnabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if opt_anonymous_auth {
		auditResult := &audit.AuditResult{
			Name:     AnonymousAuthEnabled,
			Severity: audit.Error,
			Message:  "Anonymous access is allowed",
			PendingFix: &fixAnonymousAuthEnabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	auditResults = append(auditResults, auditAPIServerKeyAndCertificates(proc.options)...)

	return auditResults
}

func auditAPIServerAuthorizationMode(auth_mode string) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	// Get the module names from the option (the option looks like) :
	// --authorization-mode=Node,RBAC,...
	parts := strings.Split(auth_mode, "=")
	if len(parts) < 2 {
		return auditResults
	}
	modules := strings.Split(parts[1], ",")

	if findName(modules, "AlwaysAllow") {
		auditResult := &audit.AuditResult{
			Name:     AuthModeAlwaysAllowEnabled,
			Severity: audit.Error,
			Message:  "The AlwaysAllow module has been added in the list of the authorization modules !",
			PendingFix: &fixAuthModeAlwaysAllowEnabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if !findName(modules, "Node") {
		auditResult := &audit.AuditResult{
			Name:     AuthModeNodeDisabled,
			Severity: audit.Error,
			Message:  "The Node module is missing in the list of the authorization modules ! This module constraints kubelet to read only the objects belonging to its Node",
			PendingFix: &fixAuthModeNodeDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if !findName(modules, "RBAC") {
		auditResult := &audit.AuditResult{
			Name:     AuthModeRBACDisabled,
			Severity: audit.Error,
			Message:  "The RBAC is missing in the list of the authorization modules !",
			PendingFix: &fixAuthModeRBACDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}

func auditAPIServerEnableAdmissionPlugins(plugins_opt string) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	// Get the module names from the option (the option looks like) :
	// --enable-admission-plugins=EventrateLimit,AlwaysPullImages,...
	parts := strings.Split(plugins_opt, "=")
	if len(parts) < 2 {
		return auditResults
	}
	plugins := strings.Split(parts[1], ",")

	// Some Plugins are enabled by default, we check the following modules should be enabled :
	// EventRateLimit, AlwaysPullImages, SecurityContextDeny, ServiceAccount, NamespaceLifecycle, PodSecurityPolicy, NodeRestriction
	// AlwaysAdmit must not be enabled

	if !findName(plugins, "EventRateLimit") {
		auditResult := &audit.AuditResult{
			Name:     AdmissionControllerEventRateLimitDisabled,
			Severity: audit.Warn,
			Message:  "The EventRateLimit admission controller module is disabled ! This module is useful to mitigate the DoS",
			PendingFix: &fixAdmissionControllerEventRateLimitDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if findName(plugins, "AlwaysAdmit") {
		auditResult := &audit.AuditResult{
			Name:     AdmissionControllerAlwaysAdmitEnabled,
			Severity: audit.Error,
			Message:  "The AlwaysAdmit admission controller module is enabled ! This module should *not* be enabled !",
			PendingFix: &fixAdmissionControllerAlwaysAdmitEnabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if !findName(plugins, "AlwaysPullImages") {
		auditResult := &audit.AuditResult{
			Name:     AdmissionControllerAlwaysPullImagesDisabled,
			Severity: audit.Warn,
			Message:  "The AlwaysPullImages admission controller module is disabled ! This module is useful to avoid insecure local Images",
			PendingFix: &fixAdmissionControllerAlwaysPullImagesDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if !findName(plugins, "SecurityContextDeny") {
		auditResult := &audit.AuditResult{
			Name:     AdmissionControllerSecurityContextDenyDisabled,
			Severity: audit.Warn,
			Message:  "The SecurityContextDeny admission controller module is disabled ! This module is useful to avoid launching POD without any POD Security Policy",
			PendingFix: &fixAdmissionControllerSecurityContextDenyDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if !findName(plugins, "ServiceAccount") {
		auditResult := &audit.AuditResult{
			Name:     AdmissionControllerServiceAccountDisabled,
			Severity: audit.Warn,
			Message:  "The ServiceAccount admission controller module is disabled ! This module is useful to associate the 'default' serviceAccount when missing",
			PendingFix: &fixAdmissionControllerServiceAccountDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if !findName(plugins, "NamespaceLifecycle") {
		auditResult := &audit.AuditResult{
			Name:     AdmissionControllerNamespaceLifecycleDisabled,
			Severity: audit.Warn,
			Message:  "The NamespaceLifecycle admission controller module is disabled ! This module is useful avoid the creation of objects attached to a missing namespace",
			PendingFix: &fixAdmissionControllerNamespaceLifecycleDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if !findName(plugins, "PodSecurityPolicy") {
		auditResult := &audit.AuditResult{
			Name:     AdmissionControllerPodSecurityPolicyDisabled,
			Severity: audit.Warn,
			Message:  "The PodSecurityPolicy admission controller module is disabled ! This module is useful validate the actions allowed for a POD",
			PendingFix: &fixAdmissionControllerPodSecurityPolicyDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if !findName(plugins, "NodeSecurity") {
		auditResult := &audit.AuditResult{
			Name:     AdmissionControllerNodeSecurityDisabled,
			Severity: audit.Warn,
			Message:  "The NodeSecurity admission controller module is disabled ! This module constraints kubelet to modify the objects owned by its Node",
			PendingFix: &fixAdmissionControllerNodeSecurityDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}

func auditAPIServerKeyAndCertificates(options []string) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	if !findPrefixName(options, "--kubelet-certificate-authority") {
		auditResult := &audit.AuditResult{
			Name:     KubeletCertificateAuthorityDisabled,
			Severity: audit.Warn,
			Message:  "The --kubelet-certificate-authority option is missing ! This option is useful to authenticate kubelet and avoid Mitm attacks",
			PendingFix: &fixKubeletCertificateAuthorityDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}

func findPrefixName(string_list []string, name string) bool {
	for _, s := range string_list {
		if strings.HasPrefix(s, name) {
			return true
		}
	}

	return false
}

func findName(strings []string, name string) bool {
	for _, s := range strings {
		if s == name {
			return true
		}
	}

	return false
}

