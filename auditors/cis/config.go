package cis

type Config struct {
	IgnoreList []string `yaml:"drop"`
	KubadmConf string `yaml:"kubeadmConf"`
	ApiserverPod string `yaml:"apiserverPod"`
	ControllerManagerPod string `yaml:"controllerManagerPod"`
	ControllerManagerConf string `yaml:"controllerManagerConf"`
	KubeSchedulerPod string `yaml:"kubeSchedulerPod"`
	KubeSchedulerConf string `yaml:"kubeSchedulerConf"`
	KubeEtcdPod string `yaml:"kubeEtcdPod"`
	KubeletConf string `yaml:"kubeletConf"`
	K8sPkiDir string `yaml:"k8sPkiDir"`
	KubeletService string `yaml:"kubeletService"`
	CNIDir string `yaml:cniDir`
}

