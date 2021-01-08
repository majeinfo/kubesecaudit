package cis

import (
	"fmt"
)

type fixAnonymousAuthEnabled struct {}

func (f *fixAnonymousAuthEnabled) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --anonymous-auth=false")
}

type fixProfilingEnabled struct {}

func (f *fixProfilingEnabled) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --profiling=false")
}

type fixServiceAccountLookupDisabled struct {}

func (f *fixServiceAccountLookupDisabled) Plan() string {
	return fmt.Sprintf("The option --service-account-lookup must be set to true (it check the Tokens and their existence in etcd, avoiding the use of deleted Tokens)")
}

type fixAuditDisabled struct {}

func (f *fixAuditDisabled) Plan() string {
	return fmt.Sprintf("Add one of these options to the api-server: --audit-log-path=/path/to/audit.log or --audit-webhook-config-file=/path/to/config")
}

type fixAuditLogMaxageNotSet struct {}

func (f *fixAuditLogMaxageNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --audit-log-maxage=value")
}

type fixAuditLogMaxsizeNotSet struct {}

func (f *fixAuditLogMaxsizeNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --audit-log-maxsize=value")
}

type fixAuditLogMaxbackupNotSet struct {}

func (f *fixAuditLogMaxbackupNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --audit-log-maxbackup=value")
}

type fixBasicAuthFileEnabled struct {}

func (f *fixBasicAuthFileEnabled) Plan() string {
	return fmt.Sprintf("Remove this option to the api-server: --basic-auth-file")
}

type fixTokenAuthFileEnabled struct {}

func (f *fixTokenAuthFileEnabled) Plan() string {
	return fmt.Sprintf("Remove this option to the api-server: --token-auth-file")
}

type fixAuthModeAlwaysAllowEnabled struct {}

func (f *fixAuthModeAlwaysAllowEnabled) Plan() string {
	return fmt.Sprintf("Remove the module AlwaysAllow from the --authorization-mode value of api-server")
}

type fixAuthModeNodeDisabled struct {}

func (f *fixAuthModeNodeDisabled) Plan() string {
	return fmt.Sprintf("Add the module Node in the --authorization-mode value of api-server")
}

type fixAuthModeRBACDisabled struct {}

func (f *fixAuthModeRBACDisabled) Plan() string {
	return fmt.Sprintf("Add the module RBAC in the --authorization-mode value of api-server")
}

type fixAdmissionControllerEventRateLimitDisabled struct {}

func (f *fixAdmissionControllerEventRateLimitDisabled) Plan() string {
	return fmt.Sprintf("Add the module EventRateLimit in the --enable-admission-plugins value of api-server")
}

type fixAdmissionControllerAlwaysPullImagesDisabled struct {}

func (f *fixAdmissionControllerAlwaysPullImagesDisabled) Plan() string {
	return fmt.Sprintf("Add the module AlwaysPullImages in the --enable-admission-plugins value of api-server")
}

type fixAdmissionControllerAlwaysAdmitEnabled struct {}

func (f *fixAdmissionControllerAlwaysAdmitEnabled) Plan() string {
	return fmt.Sprintf("Remove the module AlwaysAdmit from the --enable-admission-plugins value of api-server")
}

type fixAdmissionControllerSecurityContextDenyDisabled struct {}

func (f *fixAdmissionControllerSecurityContextDenyDisabled) Plan() string {
	return fmt.Sprintf("Add the module SecurityContextDeny to the --enable-admission-plugins value of api-server")
}

type fixAdmissionControllerServiceAccountDisabled struct {}

func (f *fixAdmissionControllerServiceAccountDisabled) Plan() string {
	return fmt.Sprintf("Add the module ServiceAccount to the --enable-admission-plugins value of api-server")
}

type fixAdmissionControllerNamespaceLifecycleDisabled struct {}

func (f *fixAdmissionControllerNamespaceLifecycleDisabled) Plan() string {
	return fmt.Sprintf("Add the module NamespaceLifecycle to the --enable-admission-plugins value of api-server")
}

type fixAdmissionControllerPodSecurityPolicyDisabled struct {}

func (f *fixAdmissionControllerPodSecurityPolicyDisabled) Plan() string {
	return fmt.Sprintf("Add the module PodSecurityPolicy to the --enable-admission-plugins value of api-server")
}

type fixAdmissionControllerNodeRestrictionDisabled struct {}

func (f *fixAdmissionControllerNodeRestrictionDisabled) Plan() string {
	return fmt.Sprintf("Add the module NodeSecurity to the --enable-admission-plugins value of api-server")
}

type fixKubeletCertificateAuthorityDisabled struct {}

func (f *fixKubeletCertificateAuthorityDisabled) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --kubelet-certificate-authorityh=/path/to/cacert")
}

type fixKubeletClientCertificateDisabled struct {}

func (f *fixKubeletClientCertificateDisabled) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --kubelet-client-certificate=/path/to/cert")
}

type fixKubeletClientKeyDisabled struct {}

func (f *fixKubeletClientKeyDisabled) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --kubelet-client-key=/path/to/key")
}

type fixTLSCertFileNotSet struct {}

func (f *fixTLSCertFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --tls-cert-file=/path/to/cert")
}

type fixTLSPrivateKeyFileNotSet struct {}

func (f *fixTLSPrivateKeyFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --tls-private-key-file=/path/to/key")
}

type fixClientCAFileNotSet struct {}

func (f *fixClientCAFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --client-ca-file=/path/to/cafile")
}

type fixEtcdCertFileNotSet struct {}

func (f *fixEtcdCertFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --etcd-certfile=/path/to/cert")
}

type fixEtcdKeyFileNotSet struct {}

func (f *fixEtcdKeyFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --etcd-keyfile=/path/to/key")
}

type fixEtcdCAFileNotSet struct {}

func (f *fixEtcdCAFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --etcd-cafile=/path/to/cacert")
}

type fixEncryptionProviderConfigNotSet struct {}

func (f *fixEncryptionProviderConfigNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --encryption-provider-config=/path/to/config")
}

type fixCMProfilingEnabled struct {}

func (f *fixCMProfilingEnabled) Plan() string {
	return fmt.Sprintf("Add this option to the controller-manager: --profiling=false")
}

type fixUserServiceAccountCredentialsNotSet struct {}

func (f *fixUserServiceAccountCredentialsNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the controller-manager: --user-service-account-credentials=true")
}

type fixServiceAccountPrivateKeyFileNotSet struct {}

func (f *fixServiceAccountPrivateKeyFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the controller-manager: --service-account-private-key-file=/path/to/key")
}

type fixRootCAFileNotSet struct {}

func (f *fixRootCAFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to the controller-manager: --root-ca-file=/path/to/ca")
}

type fixCMBindAddressNotLocal struct {}

func (f *fixCMBindAddressNotLocal) Plan() string {
	return fmt.Sprintf("Add this option to the controller-manager: --bind-address=127.0.0.1")
}

type fixSchedulerProfilingEnabled struct {}

func (f *fixSchedulerProfilingEnabled) Plan() string {
	return fmt.Sprintf("Add this option to the scheduler: --profiling=false")
}

type fixSchedulerBindAddressNotLocal struct {}

func (f *fixSchedulerBindAddressNotLocal) Plan() string {
	return fmt.Sprintf("Add this option to the scheduler: --bind-address=127.0.0.1")
}

type fixEtcdOptCertFileNotSet struct {}

func (f *fixEtcdOptCertFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to etcd: --cert-file=/path/to/cert")
}

type fixEtcdOptKeyFileNotSet struct {}

func (f *fixEtcdOptKeyFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to etcd: --key-file=/path/to/key")
}

type fixEtcdOptPeerCertFileNotSet struct {}

func (f *fixEtcdOptPeerCertFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to etcd: --peer-cert-file=/path/to/cert")
}

type fixEtcdOptPeerKeyFileNotSet struct {}

func (f *fixEtcdOptPeerKeyFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to etcd: --peer-key-file=/path/to/key")
}

type fixEtcdOptAutoTLSSet struct {}

func (f *fixEtcdOptAutoTLSSet) Plan() string {
	return fmt.Sprintf("Add this option to etcd: --auto-tls=false, or remove it !")
}

type fixEtcdOptClientCertAuthNotSSet struct {}

func (f *fixEtcdOptClientCertAuthNotSSet) Plan() string {
	return fmt.Sprintf("Add this option to etcd: --client-cert-auth=true")
}

type fixEtcdOptPeerClientCertAuthNotSSet struct {}

func (f *fixEtcdOptPeerClientCertAuthNotSSet) Plan() string {
	return fmt.Sprintf("Add this option to etcd: --peer-client-cert-auth=true")
}

type fixEtcdOptPeerAutoTLSSet struct {}

func (f *fixEtcdOptPeerAutoTLSSet) Plan() string {
	return fmt.Sprintf("Add this option to etcd: --peer-auto-tls=false, or remove it !")
}

type fixEtcdOptPeerTrustedCAFileNotSet struct {}

func (f *fixEtcdOptPeerTrustedCAFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to etcd: --peer-trusted-ca-file=/path/to/cert")
}

type fixEtcdOptTrustedCAFileNotSet struct {}

func (f *fixEtcdOptTrustedCAFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to etcd: --trusted-ca-file=/path/to/cert")
}

type fixKubeletAnonymousAuthEnabled struct {}

func (f *fixKubeletAnonymousAuthEnabled) Plan() string {
	return fmt.Sprintf("Add this option to kubelet: --anonymous-auth=false, or remove it !")
}

type fixKubeletAlwaysAllowEnabled struct {}

func (f *fixKubeletAlwaysAllowEnabled) Plan() string {
	return fmt.Sprintf("Remove AlwaysAllow from the kubelet option --authorization-mode")
}

type fixKubeletTLSCertFileNotSet struct {}

func (f *fixKubeletTLSCertFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to kubelet --tls-cert-file=/path/to/cert")
}

type fixKubeletTLSPrivateKeyFileNotSet struct {}

func (f *fixKubeletTLSPrivateKeyFileNotSet) Plan() string {
	return fmt.Sprintf("Add this option to kubelet --tls-private-key-file=/path/to/key")
}