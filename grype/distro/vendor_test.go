package distro

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/linux"
)

// vendorOSRelease writes an os-release with the given ID (the distro type's value) and VERSION_ID, ID_LIKE=alpine,
// below a temporary directory and returns that directory.
func vendorOSRelease(t *testing.T, typ Type, versionID string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "etc"), 0o755))
	content := "NAME=\"" + string(typ) + "\"\nID=" + string(typ) + "\nID_LIKE=alpine\nVERSION_ID=" + versionID +
		"\nPRETTY_NAME=\"" + string(typ) + " " + versionID + "\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte(content), 0o644))
	return dir
}

// The hyphenated vendor IDs parse in every string-form entry point (--distro, db search --os, purl qualifiers).
func TestParseDistroString_Vendor(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
		wantType    Type
	}{
		{input: string(VendorLinux) + ":stream", wantName: string(VendorLinux), wantVersion: "stream", wantType: VendorLinux},
		{input: string(VendorLinux) + ":23", wantName: string(VendorLinux), wantVersion: "23", wantType: VendorLinux},
		{input: string(VendorLinux) + "-25", wantName: string(VendorLinux), wantVersion: "25", wantType: VendorLinux},
		{input: string(VendorHardened) + ":stream", wantName: string(VendorHardened), wantVersion: "stream", wantType: VendorHardened},
		{input: string(VendorHardened) + "-23", wantName: string(VendorHardened), wantVersion: "23", wantType: VendorHardened},
		{input: string(VendorHardened) + "@25", wantName: string(VendorHardened), wantVersion: "25", wantType: VendorHardened},
		{input: "opensuse-leap:15.4", wantName: "opensuse-leap", wantVersion: "15.4", wantType: OpenSuseLeap},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version := ParseDistroString(tt.input)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
			d := NewFromNameVersion(name, version)
			assert.Equal(t, tt.wantType, d.Type, "distro type should resolve to a known type")
		})
	}
}

// VERSION_ID is passed through untouched (stream, 23, 25); ID_LIKE=alpine must not make them Alpine.
func TestNewFromRelease_Vendor(t *testing.T) {
	tests := []struct {
		name        string
		release     linux.Release
		wantType    Type
		wantVersion string
		wantLabel   string
		wantMajor   string
	}{
		{
			name:        "vendor Linux stream",
			release:     linux.Release{ID: string(VendorLinux), IDLike: []string{"alpine"}, VersionID: "stream", Version: "Stream"},
			wantType:    VendorLinux,
			wantVersion: "stream",
			wantLabel:   "stream",
		},
		{
			name:        "vendor Linux 23 (old image labelled 23)",
			release:     linux.Release{ID: string(VendorLinux), IDLike: []string{"alpine"}, VersionID: "23", Version: "23"},
			wantType:    VendorLinux,
			wantVersion: "23",
			wantMajor:   "23",
		},
		{
			name:        "vendor Linux 25",
			release:     linux.Release{ID: string(VendorLinux), IDLike: []string{"alpine"}, VersionID: "25"},
			wantType:    VendorLinux,
			wantVersion: "25",
			wantMajor:   "25",
		},
		{
			name:        "vendor hardened containers stream",
			release:     linux.Release{ID: string(VendorHardened), IDLike: []string{"alpine"}, VersionID: "stream"},
			wantType:    VendorHardened,
			wantVersion: "stream",
			wantLabel:   "stream",
		},
		{
			name:        "vendor hardened containers 25",
			release:     linux.Release{ID: string(VendorHardened), IDLike: []string{"alpine"}, VersionID: "25"},
			wantType:    VendorHardened,
			wantVersion: "25",
			wantMajor:   "25",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewFromRelease(tt.release, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.wantType, d.Type)
			assert.Equal(t, tt.wantVersion, d.VersionString())
			assert.Equal(t, tt.wantLabel, d.LabelVersion())
			assert.Equal(t, tt.wantMajor, d.MajorVersion())
			assert.Equal(t, string(tt.wantType), d.ID())
		})
	}
}
