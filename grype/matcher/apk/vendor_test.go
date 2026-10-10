package apk

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/match"
	"github.com/bell-sw/osv-internal/osvdata"

	"github.com/anchore/grype/grype/distro"
	grypematch "github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/grype/grype/vulnerability/vendordb"
	"github.com/anchore/grype/grype/vulnerability/vendordb/vendordbtest"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The vendor apk path through the OSV provider with the feed-name resolution. The fake engine stands in for the
// osv-internal module; the real range evaluation is covered by the module's tests and the integration run.
func newVendorStore(t *testing.T) (vulnerability.Provider, *vendordbtest.Engine) {
	t.Helper()
	engine := vendordbtest.New()
	expat := osvdata.Advisory{
		ID: "BELL-CVE-2025-59375", CVE: "CVE-2025-59375", Introduced: "2.5.0-r0", Fixed: "2.7.2-r0", Severity: "HIGH",
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", CVSSScore: 7.5,
	}
	affected := func(v string) bool { return strings.HasPrefix(v, "2.5.") || strings.HasPrefix(v, "2.6.") }
	engine.Add(osvinternal.Ecosystem(vendordb.EcosystemLinux, "23"), "expat", expat, affected)
	engine.Add(osvinternal.Ecosystem(vendordb.EcosystemHardened, "23"), "expat", expat, affected)
	engine.Add(osvinternal.Ecosystem(vendordb.EcosystemLinux, "23"), "openjdk21-lite", osvdata.Advisory{
		ID: "BELL-CVE-2025-30754", CVE: "CVE-2025-30754", Introduced: "0", Fixed: "21.0.8_p12-r0", Severity: "MEDIUM",
	}, func(v string) bool { return strings.HasPrefix(v, "21.0.2") })

	// NVD knows a CVE for expat that the vendor feed does not, and one it does (which must be de-duplicated)
	nvdKnown := vulnerability.Vulnerability{
		Reference:   vulnerability.Reference{ID: "CVE-2025-59375", Namespace: "nvd:cpe"},
		PackageName: "expat",
		Constraint:  version.MustGetConstraint("< 2.7.2", version.UnknownFormat),
		CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:a:libexpat_project:libexpat:*:*:*:*:*:*:*:*", "")},
	}
	nvdOnly := vulnerability.Vulnerability{
		Reference:   vulnerability.Reference{ID: "CVE-2099-0001", Namespace: "nvd:cpe"},
		PackageName: "expat",
		Constraint:  version.MustGetConstraint("< 9.0", version.UnknownFormat),
		CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:a:libexpat_project:libexpat:*:*:*:*:*:*:*:*", "")},
		Fix:         vulnerability.Fix{Versions: []string{"9.0"}, State: vulnerability.FixStateFixed},
	}
	return vendordb.Wrap(mock.VulnerabilityProvider(nvdKnown, nvdOnly), engine), engine
}

func matchIDs(matches []grypematch.Match) []string {
	var out []string
	for _, m := range matches {
		out = append(out, m.Vulnerability.ID+"@"+m.Vulnerability.Namespace)
	}
	return out
}

func TestMatcherApk_Vendor_DirectMatch(t *testing.T) {
	store, engine := newVendorStore(t)
	matcher := Matcher{}
	linux23 := distro.New(distro.VendorLinux, "23", "")

	p := pkg.Package{ID: "expat-1", Name: "expat", Version: "2.6.0-r0", Type: syftPkg.ApkPkg, Distro: linux23}
	matches, ignores, err := matcher.Match(store, p)
	require.NoError(t, err)
	assert.Empty(t, ignores)
	require.Len(t, matches, 1, "%v", matchIDs(matches))
	m := matches[0]
	assert.Equal(t, "CVE-2025-59375", m.Vulnerability.ID)
	assert.Equal(t, vendordb.DistroNamespace(linux23, "23"), m.Vulnerability.Namespace)
	assert.Equal(t, []string{"2.7.2-r0"}, m.Vulnerability.Fix.Versions)
	require.NotEmpty(t, m.Details)
	assert.Equal(t, grypematch.ExactDirectMatch, m.Details[0].Type)
	assert.Equal(t, grypematch.ApkMatcher, m.Details[0].Matcher)
	dp, ok := m.Details[0].SearchedBy.(grypematch.DistroParameters)
	require.True(t, ok, "%T", m.Details[0].SearchedBy)
	assert.Equal(t, string(distro.VendorLinux), dp.Distro.Type)
	assert.Equal(t, "23", dp.Distro.Version)
	assert.Equal(t, "expat", dp.Package.Name)
	assert.Contains(t, engine.Calls, "apk "+osvinternal.Ecosystem(vendordb.EcosystemLinux, "23")+" expat@2.6.0-r0")
}

func TestMatcherApk_Vendor_FixedVersionDoesNotMatch(t *testing.T) {
	store, _ := newVendorStore(t)
	matcher := Matcher{}
	linux23 := distro.New(distro.VendorLinux, "23", "")

	p := pkg.Package{ID: "expat-2", Name: "expat", Version: "2.7.2-r0", Type: syftPkg.ApkPkg, Distro: linux23}
	matches, _, err := matcher.Match(store, p)
	require.NoError(t, err)
	assert.Empty(t, matchIDs(matches))
}

func TestMatcherApk_Vendor_IndirectMatchThroughProvidedName(t *testing.T) {
	store, _ := newVendorStore(t)
	matcher := Matcher{}
	linux23 := distro.New(distro.VendorLinux, "23", "")

	// jdk21-lite-jdk-no-deps (origin jdk21-lite) provides openjdk21-lite-jdk-no-deps; the feed keys the
	// advisory on openjdk21-lite
	p := pkg.Package{
		ID: "jdk-1", Name: "jdk21-lite-jdk-no-deps", Version: "21.0.2_p14-r1", Type: syftPkg.ApkPkg, Distro: linux23,
		Upstreams: []pkg.UpstreamPackage{{Name: "jdk21-lite"}},
		Metadata:  pkg.ApkMetadata{Provides: []string{"java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps"}},
	}
	matches, _, err := matcher.Match(store, p)
	require.NoError(t, err)
	require.Len(t, matches, 1, "%v", matchIDs(matches))
	m := matches[0]
	assert.Equal(t, "CVE-2025-30754", m.Vulnerability.ID)
	assert.Equal(t, "openjdk21-lite", m.Vulnerability.PackageName)
	assert.Equal(t, "jdk21-lite-jdk-no-deps", m.Package.Name, "the match is reported against the installed package")
	require.NotEmpty(t, m.Details)
	assert.Equal(t, grypematch.ExactIndirectMatch, m.Details[0].Type)

	// the same package without provides (an SBOM re-scan) only has the origin to go on
	p.Metadata = nil
	matches, _, err = matcher.Match(store, p)
	require.NoError(t, err)
	assert.Empty(t, matchIDs(matches), "no provided names to resolve through")
}

func TestMatcherApk_Vendor_FamiliesDoNotMix(t *testing.T) {
	store, _ := newVendorStore(t)
	matcher := Matcher{}

	hardened := distro.New(distro.VendorHardened, "23", "")
	p := pkg.Package{ID: "expat-3", Name: "expat", Version: "2.6.0-r0", Type: syftPkg.ApkPkg, Distro: hardened}
	matches, _, err := matcher.Match(store, p)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, vendordb.DistroNamespace(hardened, "23"), matches[0].Vulnerability.Namespace)

	stream := distro.New(distro.VendorHardened, "stream", "")
	p.Distro = stream
	matches, _, err = matcher.Match(store, p)
	require.NoError(t, err)
	assert.Empty(t, matchIDs(matches), "release 'stream' has no entry in the fake feed")
}

// NVD's CPE records are never consulted for the vendor distributions, neither for a CVE the feed knows nor for
// one it does not; Alpine keeps the NVD fallback.
func TestMatcherApk_Vendor_NoNvdCpeFallback(t *testing.T) {
	store, _ := newVendorStore(t)
	matcher := Matcher{}
	linux23 := distro.New(distro.VendorLinux, "23", "")
	libexpat := cpe.Must("cpe:2.3:a:libexpat_project:libexpat:2.6.0:*:*:*:*:*:*:*", "")

	p := pkg.Package{ID: "expat-4", Name: "expat", Version: "2.6.0-r0", Type: syftPkg.ApkPkg, Distro: linux23, CPEs: []cpe.CPE{libexpat}}
	matches, _, err := matcher.Match(store, p)
	require.NoError(t, err)
	assert.Equal(t, []string{"CVE-2025-59375@" + vendordb.DistroNamespace(linux23, "23")}, matchIDs(matches), "only the vendor record; no nvd:cpe row")

	// a package the feed does not know at all: nothing, whatever NVD says about its CPE
	p = pkg.Package{ID: "libexpat-1", Name: "libexpat", Version: "2.6.0-r0", Type: syftPkg.ApkPkg, Distro: linux23, CPEs: []cpe.CPE{libexpat}}
	matches, _, err = matcher.Match(store, p)
	require.NoError(t, err)
	assert.Empty(t, matchIDs(matches))

	// an unavailable archive without strict mode answers with no advisories: no finding at all, not every NVD row
	empty := vendordb.Wrap(mock.VulnerabilityProvider(), vendordbtest.New())
	p = pkg.Package{ID: "expat-7", Name: "expat", Version: "2.6.0-r0", Type: syftPkg.ApkPkg, Distro: linux23, CPEs: []cpe.CPE{libexpat}}
	matches, _, err = matcher.Match(empty, p)
	require.NoError(t, err)
	assert.Empty(t, matchIDs(matches))

	// other distros are untouched: Alpine keeps the NVD rows for CVEs its secdb does not know, fix state unknown
	p = pkg.Package{ID: "expat-8", Name: "expat", Version: "2.6.0-r0", Type: syftPkg.ApkPkg, Distro: distro.New(distro.Alpine, "3.18", ""), CPEs: []cpe.CPE{libexpat}}
	matches, _, err = matcher.Match(store, p)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"CVE-2025-59375@nvd:cpe", "CVE-2099-0001@nvd:cpe"}, matchIDs(matches))
	for _, m := range matches {
		if m.Vulnerability.ID == "CVE-2099-0001" {
			assert.Equal(t, vulnerability.FixStateUnknown, m.Vulnerability.Fix.State, "NVD fix data is not trusted for distro packages")
		}
	}
}

func TestMatcherApk_Vendor_UnknownVersionSkipped(t *testing.T) {
	store, engine := newVendorStore(t)
	matcher := Matcher{}
	p := pkg.Package{ID: "expat-5", Name: "expat", Version: "unknown", Type: syftPkg.ApkPkg, Distro: distro.New(distro.VendorLinux, "23", "")}
	matches, _, err := matcher.Match(store, p)
	require.NoError(t, err)
	assert.Empty(t, matches)
	for _, call := range engine.Calls {
		assert.False(t, strings.HasPrefix(call, "apk "), "no range evaluation for an unknown version: %s", call)
	}
}

type unavailableEngine struct {
	vendordbtest.Engine
}

func (u *unavailableEngine) APKFindings(context.Context, string, string, match.Package) ([]match.Finding, error) {
	return nil, errors.New("OSV archive is not cached and updates are disabled")
}

func (u *unavailableEngine) Advisories(context.Context, string, string, string) ([]osvdata.Advisory, error) {
	return nil, errors.New("OSV archive is not cached and updates are disabled")
}

// An unavailable vendor data source is a fatal matcher error: the scan must fail rather than report nothing.
func TestMatcherApk_Vendor_SourceUnavailableIsFatal(t *testing.T) {
	store := vendordb.Wrap(mock.VulnerabilityProvider(), &unavailableEngine{})
	matcher := Matcher{}
	p := pkg.Package{ID: "expat-6", Name: "expat", Version: "2.6.0-r0", Type: syftPkg.ApkPkg, Distro: distro.New(distro.VendorLinux, "23", "")}
	_, _, err := matcher.Match(store, p)
	require.Error(t, err)
	assert.True(t, grypematch.IsFatalError(err), "%v", err)
	assert.Contains(t, err.Error(), "OSV archive is not cached and updates are disabled")

	// other distros are not affected by the vendor source state
	alpine := pkg.Package{ID: "openssl-1", Name: "openssl", Version: "3.1.4-r0", Type: syftPkg.ApkPkg, Distro: distro.New(distro.Alpine, "3.18", "")}
	_, _, err = matcher.Match(store, alpine)
	require.NoError(t, err)
}
