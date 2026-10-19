package options

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/vulnerability/vendordb"
	osvinternal "github.com/bell-sw/osv-internal"
	"github.com/bell-sw/osv-internal/testfix"
)

func TestVendor_Defaults(t *testing.T) {
	b := defaultVendor(clio.Identification{Name: "grype"})
	require.NoError(t, b.PostLoad())
	assert.True(t, b.Enabled)
	assert.False(t, b.Strict, "an unavailable archive warns by default")
	assert.Empty(t, b.URL, "no explicit base location by default: each product keeps the module's own source")

	cfg := b.ToConfig(true)
	assert.False(t, cfg.Offline)
	assert.False(t, cfg.Strict)
	assert.Empty(t, cfg.BaseURL)
	assert.Empty(t, cfg.EcosystemURLs)

	assert.True(t, b.ToConfig(false).Offline, "db.auto-update=false means no downloads")
}

// url / feed / strict: the feed of a product wins over url; product names are case-insensitive; the setting may come
// from the flag (repeatable), the environment (comma-separated pairs) or the config file (list or map).
func TestVendor_Feeds(t *testing.T) {
	linux, hardened, jdk, nik := vendordb.EcosystemLinux, vendordb.EcosystemHardened, testfix.Product(osvinternal.KindJDK).Family, testfix.Product(osvinternal.KindNIK).Family
	want := map[string]string{
		linux:    "file:///srv/a",
		hardened: "https://mirror.example/h,v2",
		jdk:      "/srv/jdk-osv/out",
		nik:      "/srv/nik/all.zip",
	}
	tests := []struct {
		name string
		feed any
		flag []string
	}{
		{name: "environment: comma-separated pairs", feed: linux + "=file:///srv/a," + strings.ToLower(hardened) + "=https://mirror.example/h,v2," + jdk + "=/srv/jdk-osv/out," + strings.ToUpper(nik) + "=/srv/nik/all.zip"},
		{name: "config file: list", feed: []any{linux + "=file:///srv/a", hardened + "=https://mirror.example/h,v2", jdk + "=/srv/jdk-osv/out", nik + "=/srv/nik/all.zip"}},
		{name: "config file: map", feed: map[string]any{strings.ToLower(linux): "file:///srv/a", hardened: "https://mirror.example/h,v2", jdk: "/srv/jdk-osv/out", nik: "/srv/nik/all.zip"}},
		{name: "flag, repeated", flag: []string{linux + "=file:///srv/a", hardened + "=https://mirror.example/h,v2", jdk + "=/srv/jdk-osv/out", nik + "=/srv/nik/all.zip"}},
		{name: "flag entries win over the file", feed: map[string]any{jdk: "/other", linux: "file:///srv/a"}, flag: []string{strings.ToLower(jdk) + "=/srv/jdk-osv/out", hardened + "=https://mirror.example/h,v2", nik + "=/srv/nik/all.zip"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := defaultVendor(clio.Identification{Name: "grype"})
			b.URL = "https://base.example/osv"
			b.Strict = true
			if tt.feed != nil {
				b.Feed = tt.feed
			}
			b.feedFlag = tt.flag
			require.NoError(t, b.PostLoad())
			cfg := b.ToConfig(true)
			assert.Equal(t, "https://base.example/osv", cfg.BaseURL)
			assert.Equal(t, want, cfg.EcosystemURLs)
			assert.True(t, cfg.Strict)
		})
	}
}

func TestVendor_InvalidFeeds(t *testing.T) {
	jdk := testfix.Product(osvinternal.KindJDK).Family
	for _, feed := range []any{"Zulu=/z", jdk, jdk + "=", []any{42}, 7} {
		b := defaultVendor(clio.Identification{Name: "grype"})
		b.Feed = feed
		assert.Error(t, b.PostLoad(), "%v", feed)
	}
}

// The help texts of the three shared options are fixed (identical in every scanner with vendor support).
func TestVendor_HelpTexts(t *testing.T) {
	assert.Equal(t, "base location of the vendor OSV archives for all products (<url>/<product>/all.zip); http(s), file:// or a directory", vendorURLHelp)
	assert.Equal(t, `location of the vendor OSV archive of one product, as "<product>=<url>"; repeatable; products: `+strings.Join(osvinternal.Ecosystems, ", "), vendorFeedHelp)
	assert.Equal(t, "fail when vendor OSV data is unavailable instead of warning and continuing", vendorStrictHelp)
}
