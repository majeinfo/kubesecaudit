package audit

import (
	"errors"
	"fmt"
	"github.com/majeinfo/kubesecaudit/internal/k8s"
	"github.com/majeinfo/kubesecaudit/k8stypes"
	"strings"
)

type SeverityLevel int

// AuditResult severity levels. They also correspond to log levels
const (
	// Info is used for informational audit results where no action is required
	Info SeverityLevel = 0
	// Warn is used for audit results where there may be security concerns. If an auditor is disabled for a resource
	// using an override label, the audit results will be warnings instead of errors. Kubeaudit will NOT attempt to
	// fix these
	Warn SeverityLevel = 1
	// Error is used for audit results where action is required. Kubeaudit will attempt to fix these
	Error SeverityLevel = 2
)

func (s SeverityLevel) String() string {
	switch s {
	case Info:
		return "info"
	case Warn:
		return "warning"
	case Error:
		return "error"
	default:
		return "unknown"
	}
}

// Auditable is an interface which is implemented by auditors
type Auditable interface {
	Audit(resources []k8stypes.Resource) ([]*AuditResult, error)
}

// Kubeaudit provides functions to audit and fix Kubernetes manifests
type Kubeaudit struct {
	auditors []Auditable
}

// Report contains the results after auditing
type Report struct {
	results []*AuditResult
}

// New returns a new Kubeaudit instance
func New(auditors []Auditable, opts ...Option) (*Kubeaudit, error) {
	if len(auditors) == 0 {
		return nil, errors.New("no auditors enabled")
	}

	auditor := &Kubeaudit{
		auditors: auditors,
	}

	if err := auditor.parseOptions(opts); err != nil {
		return nil, err
	}

	return auditor, nil
}

// AuditLocal audits the Kubernetes resources found in the provided Kubernetes config file
func (a *Kubeaudit) AuditLocal(configpath string, options k8s.ClientOptions) (*Report, error) {
	clientset, err := k8s.NewKubeClientLocal(configpath)
	if err == k8s.ErrNoReadableKubeConfig {
		return nil, fmt.Errorf("failed to open kubeconfig file %s", configpath)
	} else if err != nil {
		return nil, err
	}

	resources := getResourcesFromClientset(clientset, options)
	results := auditResources(resources, a.auditors)

	report := &Report{results: results}

	return report, nil
}

// RawResults returns all of the results for each Kubernetes resource, including ones that had no audit results.
// Generally, you will want to use Results() instead.
/*
func (r *Report) RawResults() []Result {
	return r.results
}

 */

/*
// Results returns the audit results for each Kubernetes resource
func (r *Report) Results() []Result {
	results := make([]Result, 0, len(r.results))
	for _, result := range r.results {
		if len(result.GetAuditResults()) > 0 {
			results = append(results, result)
		}
	}
	return results
}
 */

// ResultsWithMinSeverity returns the audit results for each Kubernetes resource with a minimum severity
// Also skip Result that must be ignored
var ignore_tests []string

func (r *Report) ResultsWithMinSeverity(minSeverity SeverityLevel) []*AuditResult {
	var results []*AuditResult

	for _, result := range r.results {
		if result.Severity >= minSeverity {
			if !mustIgnore(result.Name, ignore_tests) {
				results = append(results, result)
			}
		}
	}
	return results
}

func mustIgnore(test_name string, ignores []string) bool {
	for _, ignore := range ignores {
		if ignore == test_name {
			return true
		}
	}

	return false
}

/*
// HasErrors returns true if any findings have the level of Error
func (r *Report) HasErrors() (errorsFound bool) {
	for _, workloadResult := range r.Results() {
		for _, auditResult := range workloadResult.GetAuditResults() {
			if auditResult.Severity >= Error {
				return true
			}
		}
	}
	return false
}

 */

// PrintResults writes the audit results to the specified writer. Defaults to printing results to stdout
func (r *Report) PrintResults(ignores string, printOptions ...PrintOption) {
	ignore_tests = strings.Split(ignores, ",")
	printer := NewPrinter(printOptions...)
	printer.PrintReport(r)
}

/*
// Fix tries to automatically patch any security concerns and writes the resulting manifest to the provided writer.
// Only applies when audit was performed on a manifest (not local or cluster)
func (r *Report) Fix(writer io.Writer) error {
	fixed, err := fix(r.results)
	if err != nil {
		return err
	}

	_, err = writer.Write(fixed)
	return err
}

 */

/*
// PrintPlan writes the actions that will be performed by the Fix() function in a human-readable way to the
// provided writer. Only applies when audit was performed on a manifest (not local or cluster)
func (r *Report) PrintPlan(writer io.Writer) {
	for _, result := range r.Results() {
		for _, auditResult := range result.GetAuditResults() {
			ok, plan := auditResult.FixPlan()
			if ok {
				fmt.Fprintln(writer, "* ", plan)
			}
		}
	}
}
 */


