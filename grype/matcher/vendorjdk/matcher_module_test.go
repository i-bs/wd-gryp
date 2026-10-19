package vendorjdk

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bsmatch "github.com/bell-sw/osv-internal/match"
	"github.com/bell-sw/osv-internal/osvdata"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/grype/grype/vulnerability/vendordb"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// indexEngine serves runtime queries from an in-memory index with the shared module's own range evaluation, so the
// tests below exercise the real version semantics end to end (matcher -> provider -> module).
type indexEngine struct {
	idx *osvdata.Index
}

func (e indexEngine) APKFindings(context.Context, string, string, bsmatch.Package) ([]bsmatch.Finding, error) {
	return nil, nil
}

func (e indexEngine) RuntimeFindings(_ context.Context, ecosystem, pkgName, version string) ([]bsmatch.Finding, error) {
	return bsmatch.MatchProduct(e.idx, ecosystem, pkgName, version)
}

func (e indexEngine) Advisories(context.Context, string, string, string) ([]osvdata.Advisory, error) {
	return nil, nil
}

func (e indexEngine) EOL(string) *time.Time { return nil }

func (e indexEngine) Provenance() map[string]time.Time { return nil }

// The vendor's JDK release types reach the module unchanged and untruncated: a CPU (five components, the previous PSU plus
// ".0.1") is equivalent to the PSU of its cycle when compared with an advisory's fixed version (advisories list PSU
// versions only), and a CSPU (fourth component) is newer than the PSU it is built on.
func TestVendorJDKMatcher_ReleaseTypes(t *testing.T) {
	jdk21 := jdkProduct.Ecosystem("21")
	adv := func(id, fixed string) osvdata.Advisory {
		return osvdata.Advisory{ID: "BELL-" + id, CVE: id, Ecosystem: jdk21, Package: "jdk", Introduced: "0", Fixed: fixed, Severity: "HIGH"}
	}
	engine := indexEngine{idx: osvdata.New(jdkProduct.Family,
		adv("CVE-2099-0010", "21.0.10+10"),
		adv("CVE-2099-0011", "21.0.11+11"),
		adv("CVE-2099-0012", "21.0.12.1+1"),
	)}
	store := vendordb.Wrap(mock.VulnerabilityProvider(), engine)
	m := NewVendorJDKMatcher()

	tests := []struct {
		name    string
		version string
		want    []string
	}{
		{"CPU of the 21.0.10 cycle: fixed by 21.0.10+10, affected by later fixes", "21.0.9.0.1+1", []string{"CVE-2099-0011", "CVE-2099-0012"}},
		{"PSU 21.0.10+10", "21.0.10+10", []string{"CVE-2099-0011", "CVE-2099-0012"}},
		{"PSU 21.0.9+10 is older than its CPU", "21.0.9+10", []string{"CVE-2099-0010", "CVE-2099-0011", "CVE-2099-0012"}},
		{"PSU 21.0.12+10 is older than the CSPU fix", "21.0.12+10", []string{"CVE-2099-0012"}},
		{"CSPU 21.0.12.1+1 carries the fix", "21.0.12.1+1", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg.Package{ID: pkg.ID(tt.version), Name: "jdk", Version: tt.version, Type: jdkType, Language: syftPkg.Java}
			matches, _, err := m.Match(store, p)
			require.NoError(t, err)
			var got []string
			for _, mm := range matches {
				got = append(got, mm.Vulnerability.ID)
				assert.Equal(t, tt.version, mm.Package.Version, "the installed version is reported verbatim")
				assert.Equal(t, vendordb.RuntimeNamespace(jdk21), mm.Vulnerability.Namespace)
			}
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}
