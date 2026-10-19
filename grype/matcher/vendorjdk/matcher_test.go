package vendorjdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/osvdata"
	"github.com/bell-sw/osv-internal/testfix"
	osvjdk "github.com/bell-sw/osv-internal/vendorjdk"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/grype/grype/vulnerability/vendordb"
	"github.com/anchore/grype/grype/vulnerability/vendordb/vendordbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The first JDK and NIK families of the module: the fixtures are theirs.
var (
	jdkProduct = testfix.Product(osvinternal.KindJDK)
	nikProduct = testfix.Product(osvinternal.KindNIK)
	jdkType    = syftPkg.VendorRuntimeType(jdkProduct.Family)
	nikType    = syftPkg.VendorRuntimeType(nikProduct.Family)
)

func TestVendorJDKMatcher(t *testing.T) {
	jdk21, jdk8, nik2321 := jdkProduct.Ecosystem("21"), jdkProduct.Ecosystem("8"), nikProduct.Ecosystem("23-21")
	engine := vendordbtest.New()
	engine.Add(jdk21, "jdk", osvdata.Advisory{
		ID: "BELL-CVE-2025-24855", CVE: "CVE-2025-24855", Introduced: "21.0.1+12", Fixed: "21.0.8+12", Severity: "HIGH",
	}, func(v string) bool { return v == "21.0.2+14" })
	engine.Add(jdk21, "jdk", osvdata.Advisory{
		ID: "BELL-CVE-2025-30754", CVE: "CVE-2025-30754", Introduced: "0", Fixed: "21.0.8+12", Severity: "MEDIUM",
	}, func(v string) bool { return v == "21.0.2+14" })
	engine.Add(jdk8, "jdk", osvdata.Advisory{
		ID: "BELL-CVE-2025-24855", CVE: "CVE-2025-24855", Introduced: "0", Fixed: "8u462+11", Severity: "HIGH",
	}, func(v string) bool { return v == "8u402+7" })
	store := vendordb.Wrap(mock.VulnerabilityProvider(), engine)
	m := NewVendorJDKMatcher()

	engine.Add(nik2321, "core", osvdata.Advisory{
		ID: "BELL-CVE-2025-23165", CVE: "CVE-2025-23165", Introduced: "0", Fixed: "23.1.8+1", Severity: "HIGH",
	}, func(v string) bool { return v == "23.1.0+1" })

	assert.Equal(t, syftPkg.VendorRuntimeTypes(), m.PackageTypes(), "one package type per product family of the module")
	assert.Contains(t, m.PackageTypes(), jdkType)
	assert.Contains(t, m.PackageTypes(), nikType)
	assert.Equal(t, match.VendorJDKMatcher, m.Type())

	t.Run("jdk 21.0.2+14 is affected by both advisories", func(t *testing.T) {
		p := pkg.Package{ID: "jdk21", Name: "jdk", Version: "21.0.2+14", Type: jdkType, Language: syftPkg.Java,
			PURL: osvjdk.PURL(jdkProduct.Family, osvjdk.VariantJDK, "21.0.2+14")}
		matches, ignores, err := m.Match(store, p)
		require.NoError(t, err)
		assert.Empty(t, ignores)
		require.Len(t, matches, 2)
		ids := map[string]match.Match{}
		for _, mm := range matches {
			ids[mm.Vulnerability.ID] = mm
		}
		require.Contains(t, ids, "CVE-2025-24855")
		require.Contains(t, ids, "CVE-2025-30754")
		mm := ids["CVE-2025-24855"]
		assert.Equal(t, vendordb.RuntimeNamespace(jdk21), mm.Vulnerability.Namespace)
		assert.Equal(t, []string{"21.0.8+12"}, mm.Vulnerability.Fix.Versions)
		assert.Equal(t, "jdk", mm.Package.Name)
		require.NotEmpty(t, mm.Details)
		assert.Equal(t, match.ExactDirectMatch, mm.Details[0].Type)
		assert.Equal(t, match.VendorJDKMatcher, mm.Details[0].Matcher)
		ep, ok := mm.Details[0].SearchedBy.(match.EcosystemParameters)
		require.True(t, ok, "%T", mm.Details[0].SearchedBy)
		assert.Equal(t, "java", ep.Language)
		assert.Equal(t, "jdk", ep.Package.Name)
		assert.Equal(t, "21.0.2+14", ep.Package.Version)
	})

	t.Run("jdk 8u402+7 uses the JDK:8 ecosystem", func(t *testing.T) {
		p := pkg.Package{ID: "jdk8", Name: "jdk", Version: "8u402+7", Type: jdkType, Language: syftPkg.Java}
		matches, _, err := m.Match(store, p)
		require.NoError(t, err)
		require.Len(t, matches, 1)
		assert.Equal(t, vendordb.RuntimeNamespace(jdk8), matches[0].Vulnerability.Namespace)
		assert.Equal(t, []string{"8u462+11"}, matches[0].Vulnerability.Fix.Versions)
	})

	t.Run("fixed runtime has no matches", func(t *testing.T) {
		p := pkg.Package{ID: "jdk21f", Name: "jdk", Version: "21.0.8+12", Type: jdkType, Language: syftPkg.Java}
		matches, _, err := m.Match(store, p)
		require.NoError(t, err)
		assert.Empty(t, matches)
	})

	t.Run("a CSPU version (fourth component) reaches the engine unchanged", func(t *testing.T) {
		p := pkg.Package{ID: "jdk21cspu", Name: "jdk", Version: "21.0.12.1+1", Type: jdkType, Language: syftPkg.Java}
		matches, _, err := m.Match(store, p)
		require.NoError(t, err)
		assert.Empty(t, matches)
		assert.Contains(t, engine.Calls, "runtime "+jdk21+" jdk@21.0.12.1+1")
	})

	t.Run("other variants are keyed separately", func(t *testing.T) {
		p := pkg.Package{ID: "jre21", Name: "jre", Version: "21.0.2+14", Type: jdkType, Language: syftPkg.Java}
		matches, _, err := m.Match(store, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "the fake feed has entries for jdk only")
	})

	t.Run("nik 23.1.0+1 core uses the NIK:23-21 ecosystem", func(t *testing.T) {
		p := pkg.Package{ID: "nik23", Name: "core", Version: "23.1.0+1", Type: nikType, Language: syftPkg.Java,
			PURL:     osvjdk.PURL(nikProduct.Family, osvjdk.BundleCore, "23.1.0+1"),
			Metadata: pkg.JavaVMInstallationMetadata{Release: pkg.JavaVMReleaseMetadata{JavaVersion: "21+37"}}}
		matches, _, err := m.Match(store, p)
		require.NoError(t, err)
		require.Len(t, matches, 1)
		assert.Equal(t, "CVE-2025-23165", matches[0].Vulnerability.ID)
		assert.Equal(t, vendordb.RuntimeNamespace(nik2321), matches[0].Vulnerability.Namespace)
		assert.Equal(t, []string{"23.1.8+1"}, matches[0].Vulnerability.Fix.Versions)
		assert.Equal(t, match.VendorJDKMatcher, matches[0].Details[0].Matcher)
	})

	t.Run("nik of another java line is keyed separately", func(t *testing.T) {
		p := pkg.Package{ID: "nik23-17", Name: "core", Version: "23.1.0+1", Type: nikType, Language: syftPkg.Java,
			Metadata: pkg.JavaVMInstallationMetadata{Release: pkg.JavaVMReleaseMetadata{JavaVersion: "17.0.9"}}}
		matches, _, err := m.Match(store, p)
		require.NoError(t, err)
		assert.Empty(t, matches)
	})

	t.Run("unknown version is skipped", func(t *testing.T) {
		p := pkg.Package{ID: "jdkx", Name: "jdk", Version: "unknown", Type: jdkType, Language: syftPkg.Java}
		matches, _, err := m.Match(store, p)
		require.NoError(t, err)
		assert.Empty(t, matches)
	})
}
