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

	options := buildMapFromOptions(proc.options)

	if value, found := options["authorization-mode"]; found {
		auditResults = append(auditResults, auditAPIServerAuthorizationMode(value)...)
	}

	if value, found := options["enable-admission-plugins"]; found {
		auditResults = append(auditResults, auditAPIServerEnableAdmissionPlugins(value)...)
	}

	if _, found := options["basic-auth-file"]; found {
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

	if _, found := options["token-auth-file"]; found {
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

	// --anonymous-auth=true by default
	if value, found := options["anonymous-auth"]; !found || (found && value == "true") {
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

	// --service-account-lookup=true by default
	if value, found := options["service-account-lookup"]; found && value == "false" {
		auditResult := &audit.AuditResult{
			Name:     ServiceAccountLookupDisabled,
			Severity: audit.Error,
			Message:  "Service account lookup is disabled",
			PendingFix: &fixServiceAccountLookupDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["service-account-key-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     ServiceAccountLookupDisabled,
			Severity: audit.Error,
			Message:  "Service account lookup is disabled",
			PendingFix: &fixServiceAccountLookupDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if value, found := options["profiling"]; !found || value == "true" {
		auditResult := &audit.AuditResult{
			Name:     ProfilingEnabled,
			Severity: audit.Error,
			Message:  "Profiling is enabled: it may slow down the Cluster and produce information leaks",
			PendingFix: &fixProfilingEnabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	_, found1 := options["audit-log-path"]
	_, found2 := options["audit-webhook-config-file"]

	if !found1 && !found2 {
		auditResult := &audit.AuditResult{
			Name:     AuditDisabled,
			Severity: audit.Error,
			Message:  "Auditing is disabled. It is considered a best practice to audit the calls made to the api-server",
			PendingFix: &fixAuditDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if found1 {
		auditResults = append(auditResults, auditAPIServerAuditLog(options)...)
	}

	auditResults = append(auditResults, auditAPIServerKeyAndCertificates(options)...)
	auditResults = append(auditResults, auditAPIServerEtcd(options)...)

	// TODO: audit the option --tls-cipher-suites

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

	if !findName(plugins, "NodeRestriction") {
		auditResult := &audit.AuditResult{
			Name:     AdmissionControllerNodeRestrictionDisabled,
			Severity: audit.Warn,
			Message:  "The NodeRestriction admission controller module is disabled ! This module constraints kubelet to modify the objects owned by its Node",
			PendingFix: &fixAdmissionControllerNodeRestrictionDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}

func auditAPIServerKeyAndCertificates(options map[string]string) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	if _, found := options["kubelet-certificate-authority"]; !found {
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

	if _, found := options["kubelet-client-certificate"]; !found {
		auditResult := &audit.AuditResult{
			Name:     KubeletClientCertificateDisabled,
			Severity: audit.Warn,
			Message:  "The --kubelet-client-certificate option is missing ! This option is useful to authenticate towards kubelet",
			PendingFix: &fixKubeletClientCertificateDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["kubelet-client-key"]; !found {
		auditResult := &audit.AuditResult{
			Name:     KubeletClientKeyDisabled,
			Severity: audit.Warn,
			Message:  "The --kubelet-client-key option is missing ! This option is useful to authenticate towards kubelet",
			PendingFix: &fixKubeletClientKeyDisabled{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["tls-cert-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     TLSCertFileNotSet,
			Severity: audit.Warn,
			Message:  "The --tls-cert-file option is missing ! This option is useful to authenticate clients",
			PendingFix: &fixTLSCertFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["tls-private-key-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     TLSPrivateKeyFileNotSet,
			Severity: audit.Warn,
			Message:  "The --tls-private-key-file option is missing ! This option is useful to authenticate clients",
			PendingFix: &fixTLSPrivateKeyFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["client-ca-file"]; !found {
		auditResult := &audit.AuditResult{
			Name:     ClientCAFileNotSet,
			Severity: audit.Warn,
			Message:  "The --client-ca-file option is missing ! This option is useful to authenticate clients certified by one of a well-known CA",
			PendingFix: &fixClientCAFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}

// This function is called if --audit-log-path=/path/to/audit.log option has been set
func auditAPIServerAuditLog(options map[string]string) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	if _, found := options["audit-log-maxage"]; !found {
		auditResult := &audit.AuditResult{
			Name:     AuditLogMaxageNotSet,
			Severity: audit.Warn,
			Message:  "The --audit-log-maxage option is missing ! This option is useful to minimize the logs amount",
			PendingFix: &fixAuditLogMaxageNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["--audit-log-maxsize"]; !found {
		auditResult := &audit.AuditResult{
			Name:     AuditLogMaxsizeNotSet,
			Severity: audit.Warn,
			Message:  "The --audit-log-maxsize option is missing ! This option is useful to minimize the logs amount",
			PendingFix: &fixAuditLogMaxsizeNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["--audit-log-maxbackup"]; !found {
		auditResult := &audit.AuditResult{
			Name:     AuditLogMaxbackupNotSet,
			Severity: audit.Warn,
			Message:  "The --audit-log-maxbackup option is missing ! This option is useful to minimize the logs amount",
			PendingFix: &fixAuditLogMaxbackupNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}

// This function audits etcd related parameters
func auditAPIServerEtcd(options map[string]string) []*audit.AuditResult {
	var auditResults []*audit.AuditResult

	if _, found := options["etcd-certfile"]; !found {
		auditResult := &audit.AuditResult{
			Name:     EtcdCertFileNotSet,
			Severity: audit.Error,
			Message:  "The --etcd-certfile option is missing ! This option is useful to securize etcd access",
			PendingFix: &fixEtcdCertFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["etcd-keyfile"]; !found {
		auditResult := &audit.AuditResult{
			Name:     EtcdKeyFileNotSet,
			Severity: audit.Error,
			Message:  "The --etcd-keyfile option is missing ! This option is useful to securize etcd access",
			PendingFix: &fixEtcdKeyFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["etcd-cafile"]; !found {
		auditResult := &audit.AuditResult{
			Name:     EtcdCAFileNotSet,
			Severity: audit.Error,
			Message:  "The --etcd-cafile option is missing ! This option is useful to securize etcd access",
			PendingFix: &fixEtcdCAFileNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	if _, found := options["encryption-provider-config"]; !found {
		auditResult := &audit.AuditResult{
			Name:     EncryptionProviderConfigNotSet,
			Severity: audit.Warn,
			Message:  "The --encryption-provider-config option is missing ! This option is useful to encrypt etcd content",
			PendingFix: &fixEncryptionProviderConfigNotSet{},
			Metadata: audit.Metadata{
				"File": proc_apiserver,
			},
		}
		auditResults = append(auditResults, auditResult)
	}

	return auditResults
}


