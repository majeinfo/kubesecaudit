# kubesecaudit

This is originally a clone of github.com/Shopify/kubeaudit.
But the original tool is not very handy to implement global tests because
it is basically built around a main loop on some of the Cluster resources (Deployments, PODs...)
and for each resource a set of "Auditor" is launched.

In our solution, we loop on each "Auditor" and each of them may loop on the full resources.
This allow the implementation of different tests such as verifying if the PODs belonging
to the same ReplicaSet are located on different Nodes (ex: CoreDNS PODs *should* be deployed
on different Nodes to make the cluster highly available).

This also allow to implement tests which do not use some cluster resources, for example, 
we can check if the cluster components (apiserver, scheduler...) are well secured.
These tests are defined by the CIS Benchmark.

Other improvements of the original fork :
- agregates POD capabilities to minimize the summarize the output
- detects when PodAntiAffinity is needed for H-A
- analyzes the Cluster configuration
- add a command line option to ignore specific tests

