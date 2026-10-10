package osv

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bell-sw/osv-internal/testfix"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/grype/distro"
	"github.com/google/osv-scanner/pkg/models"
)

// TestVendorTransform runs the vendor strategy over a real BELL-* fixture:
// the CVE comes from the record id, constraints are emitted in apk format and
// every affected entry carries the OperatingSystem of its ecosystem (numeric
// release → MajorVersion, "stream" → LabelVersion).
func TestVendorTransform(t *testing.T) {
	tests := []transformCase{
		{
			name:        "expat CVE-2025-59375",
			fixturePath: testfix.RewriteOSVFile(t, "testdata/BELL-CVE-2025-59375.json"),
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:          "BELL-CVE-2025-59375",
					Status:        db.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2025, time.December, 23, 13, 5, 51, 859654000, time.UTC)),
					PublishedDate: timeRef(time.Date(2025, time.September, 15, 11, 56, 23, 866967000, time.UTC)),
					BlobValue: &db.VulnerabilityBlob{
						ID: "BELL-CVE-2025-59375",
						References: []db.Reference{{
							URL:  "https://docs.bell-sw.com/security/cves/CVE-2025-59375",
							Tags: []string{"ADVISORY"},
						}, {
							URL:  "https://docs.bell-sw.com/security/advisories/BELL-SA-2025-13",
							Tags: []string{"ADVISORY"},
						}},
						Aliases: []string{"CVE-2025-59375"},
						Severities: []db.Severity{{
							Scheme: db.SeveritySchemeCVSS,
							Value: db.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								Version: "3.1",
							},
						}},
					},
				},
				// ByAffectedPackage sorts on package + ranges (not OS), so the six
				// entries group by constraint: stream (2.4.9), 23 (2.5.0), 25 (2.7.1).
				Related: affectedPkgSlice(
					vendorAffected(vendorOS(string(distro.VendorLinux), "", "stream"), ">=2.4.9-r0,<2.7.2-r0"),
					vendorAffected(vendorOS(string(distro.VendorHardened), "", "stream"), ">=2.4.9-r0,<2.7.2-r0"),
					vendorAffected(vendorOS(string(distro.VendorLinux), "23", ""), ">=2.5.0-r0,<2.7.2-r0"),
					vendorAffected(vendorOS(string(distro.VendorHardened), "23", ""), ">=2.5.0-r0,<2.7.2-r0"),
					vendorAffected(vendorOS(string(distro.VendorLinux), "25", ""), ">=2.7.1-r0,<2.7.2-r0"),
					vendorAffected(vendorOS(string(distro.VendorHardened), "25", ""), ">=2.7.1-r0,<2.7.2-r0"),
				),
			}},
		},
	}
	runTransformCases(t, tests)
}

func vendorOS(name, major, label string) *db.OperatingSystem {
	return &db.OperatingSystem{Name: name, MajorVersion: major, LabelVersion: label}
}

func vendorAffected(os *db.OperatingSystem, constraint string) db.AffectedPackageHandle {
	return db.AffectedPackageHandle{
		Package: &db.Package{
			Name:      "expat",
			Ecosystem: "apk",
		},
		OperatingSystem: os,
		BlobValue: &db.PackageBlob{
			CVEs: []string{"CVE-2025-59375"},
			Ranges: []db.Range{{
				Version: db.Version{
					Type:       "apk",
					Constraint: constraint,
				},
				Fix: &db.Fix{
					Version: "2.7.2-r0",
					State:   db.FixedStatus,
				},
			}},
		},
	}
}

// TestVendorRangeConversion: ECOSYSTEM/SEMVER map to "apk" and multi-window
// ranges are comma-delimited, as the apk constraint parser requires.
func TestVendorRangeConversion(t *testing.T) {
	tests := []struct {
		name string
		rnge models.Range
		want []db.Range
	}{
		{
			name: "ecosystem introduced -> fixed apk range is comma-delimited",
			rnge: models.Range{
				Type: models.RangeEcosystem,
				Events: []models.Event{
					{Introduced: "2.5.0-r0"},
					{Fixed: "2.7.2-r0"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "apk", Constraint: ">=2.5.0-r0,<2.7.2-r0"},
				Fix:     &db.Fix{Version: "2.7.2-r0", State: db.FixedStatus},
			}},
		},
		{
			name: "semver introduced -> fixed apk range",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "1.0.0"},
					{Fixed: "1.2.0"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "apk", Constraint: ">=1.0.0,<1.2.0"},
				Fix:     &db.Fix{Version: "1.2.0", State: db.FixedStatus},
			}},
		},
		{
			name: "introduced with no upper bound stays open-ended",
			rnge: models.Range{
				Type: models.RangeEcosystem,
				Events: []models.Event{
					{Introduced: "2.4.9-r0"},
				},
			},
			want: []db.Range{{
				Version: db.Version{Type: "apk", Constraint: ">=2.4.9-r0"},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vendorRanges(tt.rnge)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// The comma normalization is local to the vendor strategy; the shared
// helper's "apk" ranges are unchanged.
func TestVendorNormalizationIsLocal(t *testing.T) {
	rnge := models.Range{
		Type: models.RangeEcosystem,
		Events: []models.Event{
			{Introduced: "2.5.0-r0"},
			{Fixed: "2.7.2-r0"},
		},
	}
	shared := getGrypeRangesFromRange(rnge, "apk")
	if len(shared) != 1 || strings.Contains(shared[0].Version.Constraint, ",") {
		t.Fatalf("shared helper output for apk ranges changed: %v", shared)
	}
	if got := normalizeConstraint(shared[0].Version.Constraint, "apk"); got != shared[0].Version.Constraint {
		t.Errorf("normalizeConstraint must leave apk constraints untouched, got %q", got)
	}
	own := vendorRanges(rnge)
	if len(own) != 1 || own[0].Version.Constraint != ">=2.5.0-r0,<2.7.2-r0" {
		t.Errorf("vendor ranges must be comma-delimited: %v", own)
	}
}
