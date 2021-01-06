package k8s

import "github.com/majeinfo/kubesecaudit/k8stypes"

func FindReplicaSetFromParent(parent string, namespace string, resources []k8stypes.Resource) []*k8stypes.ReplicaSetV1 {
	var rss []*k8stypes.ReplicaSetV1

	for _, res := range resources {
		if !k8stypes.IsReplicaSetV1(res) {
			continue
		}
		rs := res.(*k8stypes.ReplicaSetV1)
		if namespace == rs.ObjectMeta.Namespace &&
			len(rs.ObjectMeta.OwnerReferences) > 0 &&
			parent == rs.ObjectMeta.OwnerReferences[0].Name {
			rss = append(rss, rs)
		}
	}

	return rss
}

func FindPodFromParent(parent string, namespace string, resources []k8stypes.Resource) []*k8stypes.PodV1 {
	var pods []*k8stypes.PodV1

	for _, res := range resources {
		if !k8stypes.IsPodV1(res) {
			continue
		}
		pod := res.(*k8stypes.PodV1)
		if namespace == pod.ObjectMeta.Namespace &&
			len(pod.ObjectMeta.OwnerReferences) > 0 &&
			parent == pod.ObjectMeta.OwnerReferences[0].Name {
			pods = append(pods, pod)
		}
	}

	return pods
}