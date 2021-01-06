package k8stypes

func IsNamespaceV1(resource Resource) bool {
	_, ok := resource.(*NamespaceV1)
	return ok
}

func IsDeploymentV1(resource Resource) bool {
	_, ok := resource.(*DeploymentV1)
	return ok
}

func IsPodV1(resource Resource) bool {
	_, ok := resource.(*PodV1)
	return ok
}

func IsReplicaSetV1(resource Resource) bool {
	_, ok := resource.(*ReplicaSetV1)
	return ok
}

