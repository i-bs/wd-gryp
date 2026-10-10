package apk

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherApk_Vendor drives the apk matcher against a DB built from a real
// vendor record. BELL-CVE-2025-59375 fixes expat 2.7.2-r0 on three release
// lines, each with its own affected floor:
//
//	Linux / hardened containers : stream  → [2.4.9-r0, 2.7.2-r0)
//	Linux / hardened containers : 23      → [2.5.0-r0, 2.7.2-r0)
//	Linux / hardened containers : 25      → [2.7.1-r0, 2.7.2-r0)
func TestMatcherApk_Vendor(t *testing.T) {
	dbtest.DBs(t, "vendor-apk").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}

		linuxStream := distro.New(distro.VendorLinux, "stream", "")
		linux23 := distro.New(distro.VendorLinux, "23", "")
		linux25 := distro.New(distro.VendorLinux, "25", "")
		hardenedStream := distro.New(distro.VendorHardened, "stream", "")

		// vulnerable expat on the rolling release (stream floor 2.4.9-r0).
		t.Run("vendor Linux stream: vulnerable expat matches", func(t *testing.T) {
			p := dbtest.NewPackage("expat", "2.6.0-r0", syftPkg.ApkPkg).
				WithDistro(linuxStream).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2025-59375").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		// same version, numbered release 23 (floor 2.5.0-r0): still vulnerable.
		t.Run("vendor Linux 23: vulnerable expat matches", func(t *testing.T) {
			p := dbtest.NewPackage("expat", "2.6.0-r0", syftPkg.ApkPkg).
				WithDistro(linux23).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2025-59375").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		// release 25 has a higher floor (2.7.1-r0), so 2.6.0-r0 is outside the
		// range: no match, but the DistroPackageFixed ignores are still emitted
		t.Run("vendor Linux 25: version outside the release range does not match", func(t *testing.T) {
			pkgID := pkg.ID("expat-linux25-below-floor")
			p := dbtest.NewPackage("expat", "2.6.0-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(linux25).
				Build()

			db.Match(t, &matcher, p).
				DoesNotHaveAnyVulnerabilities("BELL-CVE-2025-59375", "CVE-2025-59375").
				Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed", "BELL-CVE-2025-59375", "CVE-2025-59375").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// release 25 at its floor (2.7.1-r0) is vulnerable.
		t.Run("vendor Linux 25: at the release floor matches", func(t *testing.T) {
			p := dbtest.NewPackage("expat", "2.7.1-r0", syftPkg.ApkPkg).
				WithDistro(linux25).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2025-59375").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		// the fix (2.7.2-r0): no match, DistroPackageFixed ignores for the record
		// ID and the CVE
		t.Run("vendor Linux stream: fixed version does not match", func(t *testing.T) {
			pkgID := pkg.ID("expat-linux-stream-fixed")
			p := dbtest.NewPackage("expat", "2.7.2-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(linuxStream).
				Build()

			db.Match(t, &matcher, p).
				DoesNotHaveAnyVulnerabilities("BELL-CVE-2025-59375", "CVE-2025-59375").
				Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed", "BELL-CVE-2025-59375", "CVE-2025-59375").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// the subpackage libexpat resolves through its origin expat
		t.Run("vendor Linux stream: libexpat matches via origin package expat", func(t *testing.T) {
			p := dbtest.NewPackage("libexpat", "2.6.0-r0", syftPkg.ApkPkg).
				WithDistro(linuxStream).
				WithUpstream("expat", "").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2025-59375").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})

		// the same record covers the hardened containers
		t.Run("vendor hardened containers stream: vulnerable expat matches", func(t *testing.T) {
			p := dbtest.NewPackage("expat", "2.6.0-r0", syftPkg.ApkPkg).
				WithDistro(hardenedStream).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2025-59375").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
	})
}

// TestMatcherApk_Vendor_SBOMImages drives name/version/origin tuples taken
// from real vendor image SBOMs against real records whose release lines
// diverge for the same CVE:
//
//	BELL-CVE-2026-34180 (openssl): 23 → [3.0.8-r4, 3.0.21-r0), 25 → [3.5.0-r0, 3.5.7-r0), stream → [3.1.1-r1, 3.5.7-r0)
//	BELL-CVE-2026-21637 (nodejs):  23 → fixed 20.20.0-r0, 25 → fixed 22.22.2-r0, stream → fixed 24.14.1-r0
//	BELL-CVE-2026-3219  (py3-pip): stream only → [22.3.1-r2, 26.1-r0)
func TestMatcherApk_Vendor_SBOMImages(t *testing.T) {
	dbtest.DBs(t, "vendor-apk").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}

		linuxStream := distro.New(distro.VendorLinux, "stream", "")
		linux25 := distro.New(distro.VendorLinux, "25", "")
		hardenedStream := distro.New(distro.VendorHardened, "stream", "")

		// the Linux base image: libcrypto3 3.5.6-r0 (origin openssl) is
		// one release behind the stream fix 3.5.7-r0.
		t.Run("vendor Linux base image: libcrypto3 matches openssl record via origin", func(t *testing.T) {
			p := dbtest.NewPackage("libcrypto3", "3.5.6-r0", syftPkg.ApkPkg).
				WithDistro(linuxStream).
				WithUpstream("openssl", "").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2026-34180").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})

		// libssl3 3.5.7-r0 is exactly the stream fix: no match, DistroPackageFixed
		// ignores for the record ID and the CVE
		t.Run("vendor Linux nodejs image: libssl3 at the fix boundary does not match", func(t *testing.T) {
			pkgID := pkg.ID("libssl3-at-fix-boundary")
			p := dbtest.NewPackage("libssl3", "3.5.7-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(linuxStream).
				WithUpstream("openssl", "").
				Build()

			db.Match(t, &matcher, p).
				DoesNotHaveAnyVulnerabilities("BELL-CVE-2026-34180", "CVE-2026-34180").
				Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed", "BELL-CVE-2026-34180", "CVE-2026-34180").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// an older nodejs 24 image: nodejs 24.14.0-r0 is below the
		// stream fix 24.14.1-r0.
		t.Run("nodejs 24 image: vulnerable nodejs matches", func(t *testing.T) {
			p := dbtest.NewPackage("nodejs", "24.14.0-r0", syftPkg.ApkPkg).
				WithDistro(linuxStream).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2026-21637").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		// the same nodejs on release 25, which tracks the 22.x line (fixed
		// 22.22.2-r0): outside its window
		t.Run("nodejs 24 on vendor Linux 25: different release line does not match", func(t *testing.T) {
			pkgID := pkg.ID("nodejs-linux25-different-line")
			p := dbtest.NewPackage("nodejs", "24.14.0-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(linux25).
				Build()

			db.Match(t, &matcher, p).
				DoesNotHaveAnyVulnerabilities("BELL-CVE-2026-21637", "CVE-2026-21637").
				Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed", "BELL-CVE-2026-21637", "CVE-2026-21637").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// py3-pip 26.1.2-r0 is above the fix 26.1-r0
		t.Run("hardened python image: patched py3-pip does not match", func(t *testing.T) {
			pkgID := pkg.ID("py3-pip-hardened-patched")
			p := dbtest.NewPackage("py3-pip", "26.1.2-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(hardenedStream).
				Build()

			db.Match(t, &matcher, p).
				DoesNotHaveAnyVulnerabilities("BELL-CVE-2026-3219", "CVE-2026-3219").
				Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed", "BELL-CVE-2026-3219", "CVE-2026-3219").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// py3-pip-pyc 25.2-r0 resolves through its origin py3-pip
		t.Run("hardened: earlier py3-pip-pyc matches via origin py3-pip", func(t *testing.T) {
			p := dbtest.NewPackage("py3-pip-pyc", "25.2-r0", syftPkg.ApkPkg).
				WithDistro(hardenedStream).
				WithUpstream("py3-pip", "").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2026-3219").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})
	})
}

// The same package name and version on Alpine or Wolfi never matches a
// BELL-* record (and gets no ignore rule from one).
func TestMatcherApk_Vendor_OtherDistrosUntouched(t *testing.T) {
	dbtest.DBs(t, "vendor-apk").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		for name, d := range map[string]*distro.Distro{
			"alpine 3.18":   dbtest.Alpine318,
			"alpine 3.23":   distro.New(distro.Alpine, "3.23.0", ""),
			"wolfi rolling": distro.New(distro.Wolfi, "", ""),
		} {
			t.Run(name, func(t *testing.T) {
				// vulnerable on every vendor release line (see TestMatcherApk_Vendor)
				p := dbtest.NewPackage("expat", "2.7.1-r0", syftPkg.ApkPkg).
					WithDistro(d).
					Build()

				findings := db.Match(t, &matcher, p)
				findings.IsEmpty()
				findings.Ignores().IsEmpty()
			})
		}
	})
}

// ...and the reverse: Alpine secdb records never reach a package installed on
// the vendor distributions.
func TestMatcherApk_Vendor_AlpineRecordsDoNotApply(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			for name, d := range map[string]*distro.Distro{
				"vendor Linux stream":               distro.New(distro.VendorLinux, "stream", ""),
				"vendor Linux 23":                   distro.New(distro.VendorLinux, "23", ""),
				"vendor hardened containers stream": distro.New(distro.VendorHardened, "stream", ""),
			} {
				t.Run(name, func(t *testing.T) {
					// vulnerable on alpine 3.18 (see TestMatcherApk_DirectMatch_Alpine)
					p := dbtest.NewPackage("openssl", "3.1.4-r0", syftPkg.ApkPkg).
						WithDistro(d).
						Build()

					findings := db.Match(t, &matcher, p)
					findings.IsEmpty()
					findings.Ignores().IsEmpty()
				})
			}
		})
}
