package cis

// Implements the CIS Benchmark tests
// TODO: when processes are executed as POD, should map the filename with the real filename from the outside point of view

import (
	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/k8stypes"
)

const Name = "cis"

// Possible Audit Messages
const (
	// Files and directories
	FileError = "FileError"
	FilePermsError = "FilePermsError"
	FileOwnerError = "FileOwnerError"
	FileGroupOwnerError = "FileGroupOwnerError"

	// Api-server
	KubeApiServerNotFound = "KubeApiServerNotFound"
	AnonymousAuthEnabled = "AnonymousAuthEnabled"
	ProfilingEnabled = "ProfilingEnabled"
	AuditDisabled = "AuditDisabled"
	AuditLogMaxageNotSet = "AuditLogMaxageNotSet"
	AuditLogMaxsizeNotSet = "AuditLogMaxsizeNotSet"
	AuditLogMaxbackupNotSet = "AuditLogMaxbackupNotSet"
	ServiceAccountLookupDisabled = "ServiceAccountLookupDisabled"
	BasicAuthFileDefined = "BasicAuthFileDefined"
	TokenAuthFileDefined = "TokenAuthFileDefined"
	AuthModeAlwaysAllowEnabled = "AuthModeAlwaysAllowEnabled"
	AuthModeNodeDisabled = "AuthModeNodeDisabled"
	AuthModeRBACDisabled = "AuthModeRBACDisabled"
	AdmissionControllerEventRateLimitDisabled = "AdmissionControllerEventRateLimitDisabled"
	AdmissionControllerAlwaysPullImagesDisabled = "AdmissionControllerAlwaysPullImagesDisabled"
	AdmissionControllerAlwaysAdmitEnabled = "AdmissionControllerAlwaysAdmitEnabled"
	AdmissionControllerSecurityContextDenyDisabled = "AdmissionControllerSecurityContextDenyDisabled"
	AdmissionControllerServiceAccountDisabled = "AdmissionControllerServiceAccountDisabled"
	AdmissionControllerNamespaceLifecycleDisabled = "AdmissionControllerNamespaceLifecycleDisabled"
	AdmissionControllerPodSecurityPolicyDisabled = "AdmissionControllerPodSecurityPolicyDisabled"
	AdmissionControllerNodeRestrictionDisabled = "AdmissionControllerNodeRestrictionDisabled"
	KubeletCertificateAuthorityDisabled = "KubeletCertificateAuthorityDisabled"
	KubeletClientCertificateDisabled = "KubeletClientCertificateDisabled"
	KubeletClientKeyDisabled = "KubeletClientKeyDisabled"
	TLSCertFileNotSet = "TLSCertFileNotSet"
	TLSPrivateKeyFileNotSet = "TLSPrivateKeyFileNotSet"
	ClientCAFileNotSet = "ClientCAFileNotSet"
	EtcdCertFileNotSet = "EtcdCertFileNotSet"
	EtcdKeyFileNotSet = "EtcdKeyFileNotSet"
	EtcdCAFileNotSet = "EtcdCAFileNotSet"
	EncryptionProviderConfigNotSet = "EncryptionProviderConfigNotSet"

	// Controller Manager
	KubeControllerManagerNotFound = "KubeControllerManagerNotFound"
	CMProfilingEnabled = "CMProfilingEnabled"
	UserServiceAccountCredentialsNotSet = "UserServiceAccountCredentialsNotSet"
	ServiceAccountPrivateKeyFileNotSet = "ServiceAccountPrivateKeyFileNotSet"
	RootCAFileNotSet = "RootCAFileNotSet"
	CMBindAddressNotLocal = "CMBindAddressNotLocal"

	// Scheduler
	KubeSchedulerNotFound = "KubeSchedulerNotFound"
	SchedulerProfilingEnabled = "SchedulerProfilingEnabled"
	SchedulerBindAddressNotLocal = "SchedulerBindAddressNotLocal"

	// Kubelet
	KubeletNotFound = "KubeletNotFound"
	KubeletAnonymousAuthEnabled = "KubeletAnonymousAuthEnabled"
	KubeletAlwaysAllowEnabled = "KubeletAlwaysAllowEnabled"
	KubeletTLSCertFileNotSet = "KubeletTLSCertFileNotSet"
	KubeletTLSPrivateKeyFileNotSet = "KubeletTLSPrivateKeyFileNotSet"
	KubeletReadOnlyPortEnabled = "KubeletReadOnlyPortEnabled"
	KubeletProtectKernelDefaultsDisabled = "KubeletProtectKernelDefaultsDisabled"
	KubeletMakeIptablesutilChainsDisabled = "KubeletMakeIptablesutilChainsDisabled"

	// Etcd
	EtcdNotFound = "EtcdNotFound"
	EtcdOptCertFileNotSet = "EtcdOptCertFileNotSet"
	EtcdOptKeyFileNotSet = "EtcdOptKeyFileNotSet"
	EtcdOptPeerCertFileNotSet = "EtcdOptPeerCertFileNotSet"
	EtcdOptPeerKeyFileNotSet = "EtcdOptPeerKeyFileNotSet"
	EtcdOptAutoTLSSet = "EtcdOptAutoTLSSet"
	EtcdOptClientCertAuthNotSSet = "EtcdOptAClientCertAuthNotSSet"
	EtcdOptPeerClientCertAuthNotSSet = "EtcdOptPeerClientCertAuthNotSSet"
	EtcdOptPeerAutoTLSSet = "EtcdOptPeerAutoTLSSet"
	EtcdOptPeerTrustedCAFileNotSet = "EtcdOptPeerTrustedCAFileNotSet"
	EtcdOptTrustedCAFileNotSet = "EtcdOptTrustedCAFileNotSet"
)

type fileToAudit struct {
	fname string
	owner string
	group string
	perms int
}
var filesToAudit map[string]*fileToAudit

// ClusterArchitectureRules implements Auditable and GlobalAudit
type CISConfig struct{
	config Config
}

const (
	conf_kubadmConf = "kubadmConf"
	conf_apiserverPod = "apiserverPod"
	conf_controllerManagerPod = "controllerManagerPod"
	conf_controllerManagerConf = "controllerManagerConf"
	conf_kubeSchedulerPod = "kubeSchedulerPod"
	conf_kubeSchedulerConf = "kubeSchedulerConf"
	conf_kubeEtcdPod = "kubeEtcdPod"
	conf_kubeletConf = "kubeletConf"
	conf_k8sPkiDir = "k8sPkiDir"
	conf_kubeletService = "kubeletService"
	conf_cniDir = "cniDir"

	proc_apiserver = "kube-apiserver"
	proc_controller_manager = "kube-controller-manager"
	proc_scheduler = "kube-scheduler"
	proc_kubelet = "kubelet"
	proc_etcd = "etcd"
)

func init() {
	filesToAudit = map[string]*fileToAudit{
		conf_kubadmConf: { "/etc/kubernetes/admin.conf", "root", "root", 0640 },
		conf_apiserverPod: { "/etc/kubernetes/manifests/kube-apiserver.yaml", "root", "root", 0644 },
		conf_controllerManagerPod: { "/etc/kubernetes/manifests/kube-controller-manager.yaml", "root", "root", 0644 },
		conf_controllerManagerConf: { "/etc/kubernetes/controller-manager.conf", "root", "root", 0644 },
		conf_kubeSchedulerPod: { "/etc/kubernetes/manifests/kube-scheduler.yaml", "root", "root", 0644 },
		conf_kubeSchedulerConf: { "/etc/kubernetes/scheduler.conf", "root", "root", 0644 },
		conf_kubeEtcdPod: { "/etc/kubernetes/manifests/kube-etcd.yaml", "root", "root", 0644 },
		conf_kubeletConf: { "/etc/kubernetes/kubelet.conf", "root", "root", 0644 },
		conf_kubeletService: { "/etc/systemd/system/multi-user.target.wants/kubelet.service", "root", "root", 0644 },
		conf_k8sPkiDir: { "/etc/kubernetes/pki", "root", "root", 0755 },
		//{ "/etc/kubernetes/pki/*.crt", "root", "root", 0644 },
		//{ "/etc/kubernetes/pki/*.key", "root", "root", 0600 },
		conf_cniDir: { "/etc/cni/net.d", "root", "root", 0755 },
	}
}

func New(config Config) *CISConfig {
	return &CISConfig{
		config: config,
	}
}

// Check the best practice rules for the whole cluster
func (cis *CISConfig) Audit(resources []k8stypes.Resource) ([]*audit.AuditResult, error) {
	var auditResults []*audit.AuditResult

	auditResults = append(auditResults, auditFiles(cis)...)
	processes, err := GetAllProcesses()
	if err != nil {
		return auditResults, err
	}
	auditResults = append(auditResults, auditAPIServer(processes)...)
	auditResults = append(auditResults, auditControllerManager(processes)...)
	auditResults = append(auditResults, auditScheduler(processes)...)
	auditResults = append(auditResults, auditKubelet(processes)...)
	auditResults = append(auditResults, auditEtcd(processes)...)

	return auditResults, nil
}

