package cis

import (
	"fmt"
)

type fixAnonymousAuthEnabled struct {}

func (f *fixAnonymousAuthEnabled) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --anonymous-auth=false")
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

type fixAdmissionControllerNodeSecurityDisabled struct {}

func (f *fixAdmissionControllerNodeSecurityDisabled) Plan() string {
	return fmt.Sprintf("Add the module NodeSecurity to the --enable-admission-plugins value of api-server")
}

type fixKubeletCertificateAuthorityDisabled struct {}

func (f *fixKubeletCertificateAuthorityDisabled) Plan() string {
	return fmt.Sprintf("Add this option to the api-server: --kubelet-certificate-authorityh=/path/to/cacarte")
}










