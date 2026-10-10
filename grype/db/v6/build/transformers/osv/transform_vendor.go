package osv

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/versionutil"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/google/osv-scanner/pkg/models"
)

// vendorStrategy handles the BELL-* records of the vendor's vulnerability
// database: affected apk version ranges of packages shipped in its apk-based
// distributions.
//
//   - The CVE is derived from the record id (BELL-CVE-YYYY-NNNNN names the
//     CVE it assesses) plus any CVE in aliases/related; the OSV model
//     vendored here has no `upstream` field.
//   - These are distro packages (like alpine secdb): every affected entry
//     carries an OperatingSystem derived from the ecosystem string
//     ("<family>:23", "<family>:stream") so the apk
//     matcher's distro search finds them.
//   - Versions are apk-flavored (2.7.2-r0) and use the apk comparator.
//   - No qualifiers or CPEs: the records are found by distro + package name.
type vendorStrategy struct{}

func (vendorStrategy) Matches(id string) bool {
	return strings.HasPrefix(id, "BELL-")
}

func (vendorStrategy) Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	severities, err := getSeverities(vuln)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain severities: %w", err)
	}

	in := []any{
		db.VulnerabilityHandle{
			Name:          vuln.ID,
			ProviderID:    state.Provider,
			Provider:      provider.Model(state),
			Status:        db.VulnerabilityActive,
			ModifiedDate:  &vuln.Modified,
			PublishedDate: &vuln.Published,
			BlobValue: &db.VulnerabilityBlob{
				ID:          vuln.ID,
				Description: vuln.Details,
				References:  vendorReferences(vuln),
				Aliases:     vendorCVEs(vuln),
				Severities:  severities,
			},
		},
	}

	for _, aph := range vendorAffectedPackages(vuln) {
		in = append(in, aph)
	}
	return transformers.NewEntries(in...), nil
}

// vendorCVEs returns the CVE ids a vendor record assesses: the id embedded in
// the record name (BELL-CVE-2025-59375 -> CVE-2025-59375) and any CVE listed in
// aliases/related (grype main reads the OSV `upstream` field instead).
func vendorCVEs(vuln unmarshal.OSVVulnerability) []string {
	var cves []string
	seen := map[string]bool{}
	add := func(id string) {
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			cves = append(cves, id)
		}
	}
	add(strings.TrimPrefix(vuln.ID, "BELL-"))
	for _, id := range vuln.Aliases {
		add(id)
	}
	for _, id := range vuln.Related {
		add(id)
	}
	return cves
}

func vendorReferences(vuln unmarshal.OSVVulnerability) []db.Reference {
	var refs []db.Reference
	for _, ref := range vuln.References {
		refs = append(refs, db.Reference{
			URL:  ref.URL,
			Tags: []string{string(ref.Type)},
		})
	}
	return refs
}

func vendorAffectedPackages(vuln unmarshal.OSVVulnerability) []db.AffectedPackageHandle {
	if len(vuln.Affected) == 0 {
		return nil
	}
	var aphs []db.AffectedPackageHandle
	for _, affected := range vuln.Affected {
		os := vendorOSFromEcosystem(string(affected.Package.Ecosystem))
		if os == nil {
			// an unrecognized ecosystem would yield an entry without OS, unreachable
			// by the distro search: skip it loudly
			log.WithFields("id", vuln.ID, "ecosystem", affected.Package.Ecosystem, "package", affected.Package.Name).
				Warn("vendor record uses an unrecognized ecosystem; skipping (add a case to vendorOSFromEcosystem to enable)")
			continue
		}

		var ranges []db.Range
		for _, r := range affected.Ranges {
			ranges = append(ranges, vendorRanges(r)...)
		}
		aphs = append(aphs, db.AffectedPackageHandle{
			Package:         vendorPackage(affected.Package),
			OperatingSystem: os,
			BlobValue: &db.PackageBlob{
				CVEs:   vendorCVEs(vuln),
				Ranges: ranges,
			},
		})
	}
	// stable: entries for the same package+constraint on different distros
	// (Linux vs hardened containers) compare equal, so keep the record's affected order
	sort.Stable(internal.ByAffectedPackage(aphs))
	return aphs
}

// vendorRanges converts one OSV range of a vendor record. Multi-window
// constraints come out of the shared helper space-separated, which the apk
// constraint parser rejects, so they are rewritten comma-separated here
// rather than in the helper, which other strategies share.
func vendorRanges(r models.Range) []db.Range {
	rangeType := vendorRangeType(r.Type)
	ranges := getGrypeRangesFromRange(r, rangeType)
	if rangeType != "apk" {
		return ranges
	}
	for i := range ranges {
		ranges[i].Version.Constraint = versionutil.EnforceSemVerConstraint(ranges[i].Version.Constraint)
	}
	return ranges
}

func vendorPackage(p models.Package) *db.Package {
	pkgType := pkg.TypeFromPURL(p.Purl)
	return &db.Package{
		Ecosystem: pkgType.String(),
		Name:      name.Normalize(p.Name, pkgType),
	}
}

// vendorOSFromEcosystem derives the OperatingSystem from a vendor ecosystem
// string "<distro>:<version>":
//
//   - "<family>:23"     → <os-release id>, major version 23
//   - "<family>:stream" → <os-release id>, label "stream"
//
// Unrecognized ecosystems return nil.
func vendorOSFromEcosystem(ecosystem string) *db.OperatingSystem {
	base, ver, ok := strings.Cut(ecosystem, ":")
	if !ok || ver == "" {
		return nil
	}

	var osName string
	switch base {
	case "Alpaquita":
		osName = "alpaquita"
	case "BellSoft Hardened Containers":
		osName = "bellsoft-hardened-containers"
	default:
		return nil
	}

	if _, err := strconv.Atoi(ver); err == nil {
		return &db.OperatingSystem{Name: osName, MajorVersion: ver}
	}
	return &db.OperatingSystem{Name: osName, LabelVersion: ver}
}

// vendorRangeType maps an OSV range type to the grype version format: both
// SEMVER and ECOSYSTEM ranges of vendor records carry apk versions.
func vendorRangeType(t models.RangeType) string {
	switch t {
	case models.RangeSemVer, models.RangeEcosystem:
		return "apk"
	default:
		return defaultRangeType(t)
	}
}
