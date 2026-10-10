/*
Package vendorjdk matches standalone vendor runtimes found from their binaries (syft package types VendorJdkPkg and
VendorNikPkg, ecosystems "<JDK family>:<major>" and "<NIK family>:<nik major>-<java major>") against the OSV data
served by the vendordb provider. No CPE / NVD matching is attempted, so a runtime is never reported twice.
*/
package vendorjdk

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/vendordb"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct{}

func NewVendorJDKMatcher() *Matcher {
	return &Matcher{}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.VendorJdkPkg, syftPkg.VendorNikPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.VendorJDKMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	if p.Version == "" || p.Version == "unknown" {
		log.WithFields("package", p.Name).Trace("skipping vendor runtime with unknown version")
		return nil, nil, nil
	}
	rp := result.NewProvider(store, p, m.Type())
	set, err := rp.FindResults(
		search.ByEcosystem(syftPkg.Java, p.Type),
		search.ByPackageName(p.Name),
		vendordb.ByRuntime(p),
		internal.OnlyVulnerableVersions(version.New(p.Version, pkg.VersionFormat(p))),
	)
	if err != nil {
		err = fmt.Errorf("vendor jdk matcher failed for %s@%s: %w", p.Name, p.Version, err)
		if errors.Is(err, vendordb.ErrSourceUnavailable) {
			// strict mode: the archive could not be obtained and the scan must fail
			return nil, nil, match.NewFatalError(m.Type(), err)
		}
		return nil, nil, err
	}
	return set.ToMatches(), nil, nil
}
