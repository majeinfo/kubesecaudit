package all

import (
	"errors"
	"fmt"
	"github.com/majeinfo/kubesecaudit/auditors/apparmor"
	"github.com/majeinfo/kubesecaudit/auditors/asat"
	"github.com/majeinfo/kubesecaudit/auditors/mountds"
	"github.com/majeinfo/kubesecaudit/auditors/netpols"
	"github.com/majeinfo/kubesecaudit/auditors/nonroot"
	"github.com/majeinfo/kubesecaudit/auditors/privesc"
	"github.com/majeinfo/kubesecaudit/auditors/privileged"
	"github.com/majeinfo/kubesecaudit/auditors/rootfs"
	"github.com/majeinfo/kubesecaudit/auditors/seccomp"

	"github.com/majeinfo/kubesecaudit/audit"
	"github.com/majeinfo/kubesecaudit/auditors/capabilities"
	"github.com/majeinfo/kubesecaudit/auditors/cis"
	"github.com/majeinfo/kubesecaudit/auditors/cluster"
	"github.com/majeinfo/kubesecaudit/auditors/hostns"
	"github.com/majeinfo/kubesecaudit/auditors/image"
	"github.com/majeinfo/kubesecaudit/auditors/limits"
	"github.com/majeinfo/kubesecaudit/config"
)

var ErrUnknownAuditor = errors.New("Unknown auditor")

var AuditorNames = []string{
	apparmor.Name,
	asat.Name,
	capabilities.Name,
	//cis.Name,	// Must be explicitly specified
	cluster.Name,
	hostns.Name,
	image.Name,
	limits.Name,
	mountds.Name,
	netpols.Name,
	nonroot.Name,
	privesc.Name,
	privileged.Name,
	rootfs.Name,
	seccomp.Name,
}

func Auditors(conf config.KubeauditConfig) ([]audit.Auditable, error) {
	enabledAuditors := conf.GetEnabledAuditors()
	if len(enabledAuditors) == 0 {
		enabledAuditors = AuditorNames
	}

	auditors := make([]audit.Auditable, 0, len(enabledAuditors))
	for _, auditorName := range enabledAuditors {
		auditor, err := initAuditor(auditorName, conf)
		if err != nil {
			return nil, err
		}
		auditors = append(auditors, auditor)
	}

	return auditors, nil
}

func initAuditor(name string, conf config.KubeauditConfig) (audit.Auditable, error) {
	switch name {
	case apparmor.Name:
		return apparmor.New(), nil
	case asat.Name:
		return asat.New(), nil
	case capabilities.Name:
		return capabilities.New(conf.GetAuditorConfigs().Capabilities), nil
	case cis.Name:
		return cis.New(conf.GetAuditorConfigs().Cis), nil
	case cluster.Name:
		return cluster.New(), nil
	case hostns.Name:
		return hostns.New(), nil
	case image.Name:
		return image.New(conf.GetAuditorConfigs().Image), nil
	case limits.Name:
		return limits.New(conf.GetAuditorConfigs().Limits)
	case mountds.Name:
		return mountds.New(), nil
	case netpols.Name:
		return netpols.New(), nil
	case nonroot.Name:
		return nonroot.New(), nil
	case privesc.Name:
		return privesc.New(), nil
	case privileged.Name:
		return privileged.New(), nil
	case rootfs.Name:
		return rootfs.New(), nil
	case seccomp.Name:
		return seccomp.New(), nil
	}

	return nil, fmt.Errorf("unknown auditor %s: %w", name, ErrUnknownAuditor)
}

