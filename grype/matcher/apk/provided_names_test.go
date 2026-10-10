package apk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/grype/grype/vulnerability/vendordb"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// the feed keys the JDK advisory on openjdk21-lite, reached through the provided names
func providedNameStore() vulnerability.Provider {
	return mock.VulnerabilityProvider(
		vulnerability.Vulnerability{
			Reference:   vulnerability.Reference{ID: "CVE-2025-30754", Namespace: vendordb.Provider + ":distro:" + string(distro.VendorLinux) + ":23"},
			PackageName: "openjdk21-lite",
			Constraint:  version.MustGetConstraint("< 21.0.8_p12-r0", version.ApkFormat),
			Fix:         vulnerability.Fix{Versions: []string{"21.0.8_p12-r0"}, State: vulnerability.FixStateFixed},
		},
		vulnerability.Vulnerability{
			Reference:   vulnerability.Reference{ID: "CVE-2025-24855", Namespace: vendordb.Provider + ":distro:" + string(distro.VendorLinux) + ":23"},
			PackageName: "openjdk21-lite",
			Constraint:  version.MustGetConstraint(">= 21_p37-r0, < 21.0.8_p12-r0", version.ApkFormat),
			Fix:         vulnerability.Fix{Versions: []string{"21.0.8_p12-r0"}, State: vulnerability.FixStateFixed},
		},
		vulnerability.Vulnerability{
			Reference:   vulnerability.Reference{ID: "CVE-2025-59375", Namespace: vendordb.Provider + ":distro:" + string(distro.VendorLinux) + ":23"},
			PackageName: "expat",
			Constraint:  version.MustGetConstraint(">= 2.5.0-r0, < 2.7.2-r0", version.ApkFormat),
			Fix:         vulnerability.Fix{Versions: []string{"2.7.2-r0"}, State: vulnerability.FixStateFixed},
		},
		// a record keyed on a name that is both an origin and a provided name of another package
		vulnerability.Vulnerability{
			Reference:   vulnerability.Reference{ID: "CVE-2026-0001", Namespace: vendordb.Provider + ":distro:" + string(distro.VendorLinux) + ":23"},
			PackageName: "java-common",
			Constraint:  version.MustGetConstraint("< 2.0-r0", version.ApkFormat),
			Fix:         vulnerability.Fix{Versions: []string{"2.0-r0"}, State: vulnerability.FixStateFixed},
		},
	)
}

func runtimePackage(name, version, origin string, provides ...string) pkg.Package {
	return pkg.Package{
		ID:        pkg.ID(name),
		Name:      name,
		Version:   version,
		Type:      syftPkg.ApkPkg,
		Distro:    distro.New(distro.VendorLinux, "23", ""),
		Upstreams: []pkg.UpstreamPackage{{Name: origin}},
		Metadata:  pkg.ApkMetadata{Provides: provides},
	}
}

func TestProvidedNameCandidates(t *testing.T) {
	p := runtimePackage("jdk21-lite-jdk-no-deps", "21.0.2_p14-r1", "jdk21-lite",
		"java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps")
	// every provided name, then every provided name minus the sub-package suffix ("-jdk-no-deps")
	assert.Equal(t, []string{"java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps", "java", "java21", "openjdk21-lite"}, providedNameCandidates(p))

	// no suffix to strip when the package is its own origin
	p = runtimePackage("jdk21-lite", "21.0.2_p14-r1", "jdk21-lite", "openjdk21-lite")
	assert.Equal(t, []string{"openjdk21-lite"}, providedNameCandidates(p))

	// no apk metadata (SBOM re-scan without provides): nothing to try
	p.Metadata = nil
	assert.Nil(t, providedNameCandidates(p))
}

func TestMatcherApk_ProvidedNameAlias(t *testing.T) {
	store := providedNameStore()
	matcher := Matcher{}

	t.Run("advisory keyed on the suffix-stripped provided name", func(t *testing.T) {
		p := runtimePackage("jdk21-lite-jdk-no-deps", "21.0.2_p14-r1", "jdk21-lite",
			"java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps=21.0.2_p14-r1")
		// grype's apk metadata strips the =version suffix; mimic it
		p.Metadata = pkg.ApkMetadata{Provides: []string{"java-jdk-no-deps", "java21-jdk-no-deps", "openjdk21-lite-jdk-no-deps"}}
		matches, _, err := matcher.Match(store, p)
		require.NoError(t, err)
		var ids []string
		for _, m := range matches {
			ids = append(ids, m.Vulnerability.ID)
			assert.Equal(t, "jdk21-lite-jdk-no-deps", m.Package.Name, "reported against the installed package")
			assert.Equal(t, "openjdk21-lite", m.Vulnerability.PackageName)
			require.NotEmpty(t, m.Details)
			assert.Equal(t, match.ExactIndirectMatch, m.Details[0].Type)
			dp, ok := m.Details[0].SearchedBy.(match.DistroParameters)
			require.True(t, ok)
			assert.Equal(t, "openjdk21-lite", dp.Package.Name)
		}
		assert.ElementsMatch(t, []string{"CVE-2025-30754", "CVE-2025-24855"}, ids)
	})

	t.Run("fixed version through the alias does not match", func(t *testing.T) {
		p := runtimePackage("jdk21-lite-jdk-no-deps", "21.0.8_p12-r0", "jdk21-lite", "openjdk21-lite-jdk-no-deps")
		matches, _, err := matcher.Match(store, p)
		require.NoError(t, err)
		assert.Empty(t, matches)
	})

	t.Run("the origin wins over provided names", func(t *testing.T) {
		// expat is known under its origin; its provided names are never consulted
		p := runtimePackage("libexpat", "2.6.0-r0", "expat", "java-common")
		matches, _, err := matcher.Match(store, p)
		require.NoError(t, err)
		require.Len(t, matches, 1)
		assert.Equal(t, "CVE-2025-59375", matches[0].Vulnerability.ID)
	})

	t.Run("only the first known alias is used", func(t *testing.T) {
		p := runtimePackage("jdk21-lite-jdk-no-deps", "1.0-r0", "jdk21-lite", "java-common", "openjdk21-lite-jdk-no-deps")
		matches, _, err := matcher.Match(store, p)
		require.NoError(t, err)
		require.Len(t, matches, 1, "java-common is known first; openjdk21-lite is not consulted")
		assert.Equal(t, "CVE-2026-0001", matches[0].Vulnerability.ID)
	})

	t.Run("distros without the convention are untouched", func(t *testing.T) {
		p := runtimePackage("jdk21-lite-jdk-no-deps", "21.0.2_p14-r1", "jdk21-lite", "openjdk21-lite-jdk-no-deps")
		p.Distro = distro.New(distro.Alpine, "3.18", "")
		matches, _, err := matcher.Match(store, p)
		require.NoError(t, err)
		assert.Empty(t, matches)
	})
}
