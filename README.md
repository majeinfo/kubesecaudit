# kubesecaudit

This is originally a clone of [github.com/Shopify/kubeaudit](github.com/Shopify/kubeaudit).
But the original tool is not very handy to implement global tests because
it is basically built around a main loop on some of the Cluster resources (Deployments, PODs...)
and for each resource a set of "Auditor" is launched.

In our solution, we loop on each "Auditor" and each of them may loop on the full set of resources.
This allow the implementation of much various tests such as verifying if the PODs belonging
to the same ReplicaSet are located on different Nodes (ex: CoreDNS PODs *should* be deployed
on different Nodes to make the cluster highly available).

This also allow to implement tests not related to cluster resources, for example, 
we can check if the cluster components (**apiserver**, **scheduler**...) are well secured.
These tests are defined by the CIS Benchmark.

Other improvements of the original fork :
- aggregates POD capabilities to summarize the output
- detects when PodAntiAffinity is needed for H-A cluster
- analyzes the Cluster configuration
- adds a command line option to ignore specific tests

# Installation
## Download a binary

**Kubesecaudit** has official releases [here](https://github.com/majeinfo/kubesecaudit/releases)

## ..or build it !

Requirements: go v1.14+, git v2+
```
$ git clone https://github.com/majeinfo/kubesecaudit
$ cd kubesecaudit
$ go build -o kubesecaudit cmd/main.go
```

# Quick Start
**kubesecaudit** tries to connect to a cluster using the local **kubeconfig** file (**$HOME/.kube/config**). 
A different **kubeconfig** location can be specified using the **-c/--kubeconfig** flag.

```
$ kubesecaudit all -c "/path/to/config"
```

The **all** command enables all the auditors except **cis** which is devoted to the analysis of the Cluster components, not the resources (PODs, Deployments, ...).

The following command displays the possible auditors and the global parameters :

```$ kubesecaudit
Available Commands:
all          Run all audits
apparmor     Audit containers running without AppArmor
asat         Audit pods using an automatically mounted default service account
capabilities Audit containers not dropping capabilities
cis          Audit nodes with CIS Benchmark Rules
cluster      Audit K8S cluster configuration
help         Help about any command
hostns       Audit pods with hostNetwork, hostIPC or hostPID enabled
image        Audit containers not using a specified image:tag
limits       Audit containers exceeding a specified CPU or memory limit
mountds      Audit containers that mount /var/run/docker.sock
netpols      Audit namespaces that do not have a default deny network policy
nonroot      Audit containers running as root
privesc      Audit containers that allow privilege escalation
privileged   Audit containers running as privileged
rootfs       Audit containers not using a read only root filesystems
seccomp      Audit containers running without Seccomp

Flags:
-e, --exitcode int         Exit code to use if there are results with severity of "error". Conventionally, 0 is used for success and all non-zero codes for an error. (default 2)
-h, --help                 help for kubesecaudit
-c, --kubeconfig string    Path to local Kubernetes config file. Only used in local mode (default is $HOME/.kube/config)
-m, --minseverity string   Set the lowest severity level to report (one of "error", "warning", "info") (default "info")
-n, --namespace string     Only audit resources in the specified namespace. Not currently supported in manifest mode.
-o, --output string        The output format to use (one of "pretty", "logrus", "json") (default "pretty")

Use "kubesecaudit [command] --help" for more information about a command.
```

Invoking the command with an auditor name and the **--help** flag, displays the specific option for this auditor.
For example, with the **all** auditor :

```$ kubesecaudit all --help
Usage:
kubesecaudit all [flags]

Flags:
--cpu string           Max CPU limit
-d, --drop strings     List of capabilities that should be dropped (default [AUDIT_WRITE,CHOWN,DAC_OVERRIDE,FOWNER,FSETID,KILL,MKNOD,NET_BIND_SERVICE,NET_RAW,SETFCAP,SETGID,SETPCAP,SETUID,SYS_CHROOT])
-h, --help             help for all
--ignore strings       Comma separated list on Tests to ignore
-i, --image string     Image to check against
-k, --kconfig string   Path to kubesecaudit config
--memory string        Max memory limit

Global Flags:
-e, --exitcode int         Exit code to use if there are results with severity of "error". Conventionally, 0 is used for success and all non-zero codes for an error. (default 2)
-c, --kubeconfig string    Path to local Kubernetes config file. Only used in local mode (default is $HOME/.kube/config)
-m, --minseverity string   Set the lowest severity level to report (one of "error", "warning", "info") (default "info")
-n, --namespace string     Only audit resources in the specified namespace. Not currently supported in manifest mode.
-o, --output string        The output format to use (one of "pretty", "logrus", "json") (default "pretty")
```
# Configuration File

**kubesecaudit** accepts a configuration file with the **-k** or **-kconfig** option.
This YAML file can be used for two things:

- Enabling only some auditors
- Specifying configuration for auditors

The config has the following format:

```
enabledAuditors:
  # Auditors are enabled by default if they are not explicitly set to "false"
  apparmor: false
  asat: false
  capabilities: true
  hostns: true
  image: true
  limits: true
  mountds: true
  netpols: true
  nonroot: true
  privesc: true
  privileged: true
  rootfs: true
  seccomp: true
auditors:
  capabilities:
    # If no capabilities are specified and the 'capabilities' auditor is enabled,
    # a list of recommended capabilities to drop is used
    drop: ['AUDIT_WRITE', 'CHOWN']
  image:
    # If no image is specified and the 'image' auditor is enabled, WARN results
    # will be generated for containers which use an image without a tag
    image: 'myimage:mytag'
  limits:
    # If no limits are specified and the 'limits' auditor is enabled, WARN results
    # will be generated for containers which have no cpu or memory limits specified
    cpu: '750m'
    memory: '500m'
  cis:
    kubeEtcdPod: "/etc/kubernetes/manifests/etcd.yaml"
```

# Override errors

Security issues can be ignored for specific containers or pods by adding override labels. This means the auditor will produce info results instead of error results and the audit result name will have Allowed appended to it. The labels are documented in each auditor's documentation, but the general format for auditors that support overrides is as follows:

An override label consists of a key and a value.

The key is a combination of the override type (container or pod) and an override identifier which is unique to each auditor (see the docs for the specific auditor). The key can take one of two forms depending on the override type:

- Container overrides, which override the auditor for that specific container, are formatted as follows:

`container.audit.kubernetes.io/[container name].[override identifier]`

- Pod overrides, which override the auditor for all containers within the pod, are formatted as follows:

`audit.kubernetes.io/pod.[override identifier]`

If the value is set to a non-empty string, it will be displayed in the info result as the OverrideReason:

```$ kubesecaudit asat
---------------- Results for ---------------
apiVersion: v1
kind: ReplicationController
metadata:
  name: replicationcontroller
  namespace: service-account-token-true-allowed
--------------------------------------------

-- [info] AutomountServiceAccountTokenTrueAndDefaultSAAllowed
Message: Audit result overridden: Default service account with token mounted. automountServiceAccountToken should be set to 'false' or a non-default service account should be used.
Metadata:
  OverrideReason: SomeReason
```
As per Kubernetes spec, value must be 63 characters or less and must be empty or begin and end with an alphanumeric character ([a-z0-9A-Z]) with dashes (-), underscores (_), dots (.), and alphanumerics between.

Multiple override labels (for multiple auditors) can be added to the same resource.
