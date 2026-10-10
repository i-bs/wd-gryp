package options

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/anchore/clio"
	"github.com/anchore/go-homedir"
	"github.com/anchore/grype/grype/vulnerability/vendordb"
	osvinternal "github.com/bell-sw/osv-internal"
)

// Vendor configures the vendor OSV data source: "vendor:" in the config file, GRYPE_VENDOR_* in the environment;
// url / feed / strict are the option scheme shared by every scanner with vendor support.
type Vendor struct {
	Enabled bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	URL     string `yaml:"url" json:"url" mapstructure:"url"` // --vendor-url, GRYPE_VENDOR_URL
	// Feed locates the archive of single products: "<product>=<url>" entries (--vendor-feed, repeatable;
	// GRYPE_VENDOR_FEED, comma-separated pairs; in the config file a list of such entries or a map product -> url).
	Feed            any           `yaml:"feed" json:"feed" mapstructure:"feed"`
	Strict          bool          `yaml:"strict" json:"strict" mapstructure:"strict"`                               // --vendor-strict, GRYPE_VENDOR_STRICT
	CacheDir        string        `yaml:"cache-dir" json:"cache-dir" mapstructure:"cache-dir"`                      // GRYPE_VENDOR_CACHE_DIR
	CacheTTL        time.Duration `yaml:"cache-ttl" json:"cache-ttl" mapstructure:"cache-ttl"`                      // GRYPE_VENDOR_CACHE_TTL
	DownloadTimeout time.Duration `yaml:"download-timeout" json:"download-timeout" mapstructure:"download-timeout"` // GRYPE_VENDOR_DOWNLOAD_TIMEOUT

	// feedFlag receives --vendor-feed; feeds is the validated result of the flag, the environment and the file.
	feedFlag []string
	feeds    map[string]string
}

// Help texts of the three shared options; word for word the same in every scanner.
const (
	vendorURLHelp    = `base location of the vendor OSV archives for all products (<url>/<product>/all.zip); http(s), file:// or a directory`
	vendorStrictHelp = `fail when vendor OSV data is unavailable instead of warning and continuing`
)

var vendorFeedHelp = `location of the vendor OSV archive of one product, as "<product>=<url>"; repeatable; products: ` + strings.Join(osvinternal.Ecosystems, ", ")

// vendorProducts are the product (ecosystem family) names accepted in a feed entry.
var vendorProducts = []string{
	vendordb.EcosystemLinux,
	vendordb.EcosystemHardened,
	vendordb.EcosystemJDK,
	vendordb.EcosystemNIK,
}

var _ interface {
	clio.FlagAdder
	clio.FieldDescriber
	clio.PostLoader
} = (*Vendor)(nil)

func defaultVendor(id clio.Identification) Vendor {
	return Vendor{
		Enabled: true,
		// url and feed are empty by default so that each product keeps its built-in source (see DescribeFields)
		Feed:            []string{},
		CacheDir:        filepath.Join(xdg.CacheHome, id.Name),
		CacheTTL:        vendordb.DefaultCacheTTL,
		DownloadTimeout: vendordb.DefaultTimeout,
	}
}

func (b *Vendor) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&b.URL, "vendor-url", "", vendorURLHelp)
	flags.StringArrayVarP(&b.feedFlag, "vendor-feed", "", vendorFeedHelp)
	flags.BoolVarP(&b.Strict, "vendor-strict", "", vendorStrictHelp)
}

func (b *Vendor) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&b.Enabled, `use the `+osvinternal.Vendor+` OSV data for its distributions and standalone JDK / NIK runtimes`)
	descriptions.Add(&b.URL, vendorURLHelp+`; empty = the built-in source of each product: `+vendordb.DefaultBaseURL+` for `+vendordb.EcosystemLinux+` and `+vendordb.EcosystemHardened+`, `+vendordb.DefaultJDKBaseURL+` for `+vendordb.EcosystemJDK+` and `+vendordb.EcosystemNIK)
	descriptions.Add(&b.Feed, vendorFeedHelp+`; a list of entries or a map product: url; an entry wins over url`)
	descriptions.Add(&b.Strict, vendorStrictHelp)
	descriptions.Add(&b.CacheDir, `directory holding the downloaded archives and their indexes (one sub-directory per product)`)
	descriptions.Add(&b.CacheTTL, `how long a downloaded archive is reused before it is refreshed (db.auto-update=false always reuses it)`)
	descriptions.Add(&b.DownloadTimeout, `timeout for downloading one archive`)
}

func (b *Vendor) PostLoad() error {
	var err error
	if b.CacheDir, err = homedir.Expand(b.CacheDir); err != nil {
		return err
	}
	entries, err := vendorFeedEntries(b.Feed)
	if err != nil {
		return err
	}
	// the flag is the most specific setting: its entries are applied last
	b.feeds, err = parseVendorFeeds(append(entries, b.feedFlag...))
	if err != nil {
		return err
	}
	// show the effective setting in `grype config`
	if len(b.feeds) > 0 {
		var list []string
		for _, product := range vendorProducts {
			if u, ok := b.feeds[product]; ok {
				list = append(list, product+"="+u)
			}
		}
		b.Feed = list
	}
	return nil
}

// vendorFeedEntries flattens the raw feed setting into "<product>=<url>" entries: a comma-separated string (the
// environment), a list (config file) or a map product -> url (config file).
func vendorFeedEntries(raw any) ([]string, error) {
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case string:
		return splitVendorFeedList(v), nil
	case []string:
		var out []string
		for _, e := range v {
			out = append(out, splitVendorFeedList(e)...)
		}
		return out, nil
	case []any:
		var out []string
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("vendor.feed: entry %v is not a \"<product>=<url>\" string", e)
			}
			out = append(out, splitVendorFeedList(s)...)
		}
		return out, nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []string
		for _, k := range keys {
			out = append(out, fmt.Sprintf("%s=%v", k, v[k]))
		}
		return out, nil
	case map[string]string:
		return vendorFeedEntries(toAnyMap(v))
	}
	return nil, fmt.Errorf("vendor.feed: unsupported value of type %T (want a list of \"<product>=<url>\" entries or a map)", raw)
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// splitVendorFeedList splits comma-separated pairs; a comma only separates when the text after it starts another
// "<product>=" pair, so URLs containing commas survive.
func splitVendorFeedList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		name, _, isPair := strings.Cut(part, "=")
		if _, known := vendorProduct(name); (!isPair || !known) && len(out) > 0 {
			out[len(out)-1] += "," + part
			continue
		}
		if strings.TrimSpace(part) != "" {
			out = append(out, part)
		}
	}
	return out
}

// vendorProduct returns the canonical product name for a case-insensitive spelling.
func vendorProduct(name string) (string, bool) {
	name = strings.TrimSpace(name)
	for _, p := range vendorProducts {
		if strings.EqualFold(p, name) {
			return p, true
		}
	}
	return "", false
}

// parseVendorFeeds validates "<product>=<url>" entries; later entries win.
func parseVendorFeeds(entries []string) (map[string]string, error) {
	feeds := map[string]string{}
	for _, e := range entries {
		name, location, ok := strings.Cut(e, "=")
		location = strings.TrimSpace(location)
		if !ok || location == "" {
			return nil, fmt.Errorf("invalid vendor feed %q: want \"<product>=<url>\"", e)
		}
		product, known := vendorProduct(name)
		if !known {
			return nil, fmt.Errorf("invalid vendor feed %q: unknown product %q (products: %s)", e, strings.TrimSpace(name), strings.Join(vendorProducts, ", "))
		}
		feeds[product] = location
	}
	return feeds, nil
}

// ToConfig builds the adapter configuration; offline follows grype's db.auto-update setting. Precedence of the
// archive location of a product: feed entry, then url, then the built-in source.
func (b Vendor) ToConfig(autoUpdate bool) vendordb.Config {
	urls := map[string]string{}
	for product, location := range b.feeds {
		urls[product] = location
	}
	return vendordb.Config{
		BaseURL:       b.URL,
		EcosystemURLs: urls,
		CacheDir:      b.CacheDir,
		TTL:           b.CacheTTL,
		Offline:       !autoUpdate,
		Strict:        b.Strict,
		Timeout:       b.DownloadTimeout,
	}
}
