// Package advisory provides offline, distribution-aware package advisory matching.
package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

const Schema = "lasa.advisories/v1"
const MaxBytes = 32 << 20

type Record struct {
	ID            string `json:"id"`
	Distribution  string `json:"distribution"`
	Package       string `json:"package"`
	SourcePackage bool   `json:"source_package"`
	Introduced    string `json:"introduced,omitempty"`
	Fixed         string `json:"fixed,omitempty"`
	Severity      string `json:"severity"`
	Uncertain     bool   `json:"uncertain,omitempty"`
}
type Database struct {
	Schema          string     `json:"schema"`
	Source          string     `json:"source"`
	FetchedAt       time.Time  `json:"fetched_at"`
	SourceUpdatedAt *time.Time `json:"source_updated_at,omitempty"`
	ExpiresAt       time.Time  `json:"expires_at"`
	Records         []Record   `json:"records"`
}

func Decode(raw []byte) (Database, error) {
	var db Database
	if len(raw) > MaxBytes {
		return db, fmt.Errorf("advisory database exceeds 32MiB")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&db); e != nil {
		return db, fmt.Errorf("invalid advisory database: %w", e)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return db, fmt.Errorf("trailing advisory data")
	}
	if db.Schema != Schema || db.Source == "" || len(db.Source) > 2048 || db.FetchedAt.IsZero() || !db.ExpiresAt.After(db.FetchedAt) || len(db.Records) > 200000 {
		return db, fmt.Errorf("invalid advisory schema, provenance, lifetime or record budget")
	}
	seen := map[string]bool{}
	for n, r := range db.Records {
		if r.ID == "" || len(r.ID) > 256 || r.Distribution == "" || r.Package == "" || len(r.Package) > 256 || !slices.Contains([]string{"critical", "high", "medium", "low", "informational"}, r.Severity) {
			return db, fmt.Errorf("invalid advisory record %d", n)
		}
		if strings.ContainsAny(r.ID+r.Distribution+r.Package+r.Introduced+r.Fixed, "\x00\r\n") {
			return db, fmt.Errorf("control characters in advisory record %d", n)
		}
		key := r.ID + "\x00" + r.Distribution + "\x00" + r.Package + "\x00" + strconv.FormatBool(r.SourcePackage) + "\x00" + r.Introduced + "\x00" + r.Fixed
		if seen[key] {
			return db, fmt.Errorf("duplicate advisory record %d", n)
		}
		seen[key] = true
	}
	return db, nil
}
func (db Database) Fresh(now time.Time, maxAge time.Duration) error {
	if db.FetchedAt.After(now.Add(5 * time.Minute)) {
		return fmt.Errorf("advisory fetch time is in the future")
	}
	if !now.Before(db.ExpiresAt) {
		return fmt.Errorf("advisory database expired at %s", db.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if maxAge > 0 && now.Sub(db.FetchedAt) > maxAge {
		return fmt.Errorf("advisory database is older than the configured maximum age")
	}
	return nil
}
func Compare(distribution, a, b string) (int, error) {
	id, _, _ := strings.Cut(distribution, ":")
	switch id {
	case "debian", "ubuntu":
		return debian(a, b)
	case "rhel", "rocky", "almalinux", "centos", "fedora", "ol", "sles", "opensuse-leap":
		return rpm(a, b)
	default:
		return 0, fmt.Errorf("no native version comparator for distribution %q", id)
	}
}
func Affected(distribution, version string, r Record) (bool, error) {
	if r.Uncertain {
		return false, fmt.Errorf("advisory %s has an undetermined vendor status", r.ID)
	}
	if distribution != r.Distribution {
		return false, nil
	}
	if r.Introduced != "" {
		c, e := Compare(distribution, version, r.Introduced)
		if e != nil {
			return false, e
		}
		if c < 0 {
			return false, nil
		}
	}
	if r.Fixed != "" {
		c, e := Compare(distribution, version, r.Fixed)
		return c < 0, e
	}
	_, e := Compare(distribution, version, version)
	return true, e
}
func epoch(s string) (uint64, string, error) {
	if s == "" || len(s) > 512 || strings.ContainsAny(s, "\x00\r\n\t ") {
		return 0, "", fmt.Errorf("invalid native package version")
	}
	if e, v, ok := strings.Cut(s, ":"); ok {
		n, err := strconv.ParseUint(e, 10, 64)
		if err != nil || v == "" {
			return 0, "", fmt.Errorf("invalid package epoch")
		}
		return n, v, nil
	}
	return 0, s, nil
}
func sign(n int) int {
	if n < 0 {
		return -1
	}
	if n > 0 {
		return 1
	}
	return 0
}
func digit(c byte) bool { return c >= '0' && c <= '9' }
func alpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func debian(a, b string) (int, error) {
	ea, a, e := epoch(a)
	if e != nil {
		return 0, e
	}
	eb, b, e := epoch(b)
	if e != nil {
		return 0, e
	}
	if ea < eb {
		return -1, nil
	}
	if ea > eb {
		return 1, nil
	}
	split := func(v string) (string, string) {
		n := strings.LastIndexByte(v, '-')
		if n < 0 {
			return v, "0"
		}
		return v[:n], v[n+1:]
	}
	au, ar := split(a)
	bu, br := split(b)
	if c := debPart(au, bu); c != 0 {
		return c, nil
	}
	return debPart(ar, br), nil
}
func debOrder(s string) int {
	if s == "" {
		return 0
	}
	c := s[0]
	if c == '~' {
		return -1
	}
	if digit(c) {
		return 0
	}
	if alpha(c) {
		return int(c)
	}
	return int(c) + 256
}
func debPart(a, b string) int {
	for a != "" || b != "" {
		for a != "" && !digit(a[0]) || b != "" && !digit(b[0]) {
			x, y := debOrder(a), debOrder(b)
			if x != y {
				return sign(x - y)
			}
			if a != "" {
				a = a[1:]
			}
			if b != "" {
				b = b[1:]
			}
		}
		a = strings.TrimLeft(a, "0")
		b = strings.TrimLeft(b, "0")
		i, j := 0, 0
		for i < len(a) && digit(a[i]) {
			i++
		}
		for j < len(b) && digit(b[j]) {
			j++
		}
		if i != j {
			return sign(i - j)
		}
		if c := strings.Compare(a[:i], b[:j]); c != 0 {
			return c
		}
		a = a[i:]
		b = b[j:]
	}
	return 0
}
func rpm(a, b string) (int, error) {
	ea, a, e := epoch(a)
	if e != nil {
		return 0, e
	}
	eb, b, e := epoch(b)
	if e != nil {
		return 0, e
	}
	if ea < eb {
		return -1, nil
	}
	if ea > eb {
		return 1, nil
	}
	split := func(v string) (string, string) {
		n := strings.LastIndexByte(v, '-')
		if n < 0 {
			return v, ""
		}
		return v[:n], v[n+1:]
	}
	av, ar := split(a)
	bv, br := split(b)
	if c := rpmPart(av, bv); c != 0 {
		return c, nil
	}
	return rpmPart(ar, br), nil
}
func rpmPart(a, b string) int {
	for a != "" || b != "" {
		for a != "" && !digit(a[0]) && !alpha(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for b != "" && !digit(b[0]) && !alpha(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}
		at, bt := strings.HasPrefix(a, "~"), strings.HasPrefix(b, "~")
		if at || bt {
			if !at {
				return 1
			}
			if !bt {
				return -1
			}
			a = a[1:]
			b = b[1:]
			continue
		}
		ac, bc := strings.HasPrefix(a, "^"), strings.HasPrefix(b, "^")
		if ac || bc {
			if a == "" {
				return -1
			}
			if b == "" {
				return 1
			}
			if !ac {
				return 1
			}
			if !bc {
				return -1
			}
			a = a[1:]
			b = b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}
		numeric := digit(a[0])
		if numeric && !digit(b[0]) {
			return 1
		}
		if !numeric && digit(b[0]) {
			return -1
		}
		i, j := 0, 0
		for i < len(a) && (numeric && digit(a[i]) || !numeric && alpha(a[i])) {
			i++
		}
		for j < len(b) && (numeric && digit(b[j]) || !numeric && alpha(b[j])) {
			j++
		}
		x, y := a[:i], b[:j]
		if numeric {
			x = strings.TrimLeft(x, "0")
			y = strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				return sign(len(x) - len(y))
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
		a = a[i:]
		b = b[j:]
	}
	if a != "" {
		return 1
	}
	if b != "" {
		return -1
	}
	return 0
}

// Debian downloads only the official tracker over verified HTTPS. Upstream does
// not provide a detached signature for this JSON endpoint; no signature is claimed.
func Debian(ctx context.Context, release string) (Database, error) {
	db := Database{Schema: Schema, Source: "https://security-tracker.debian.org/tracker/data/json", FetchedAt: time.Now().UTC()}
	db.ExpiresAt = db.FetchedAt.Add(7 * 24 * time.Hour)
	if release == "" || strings.ContainsAny(release, "/ :\r\n\x00") {
		return db, fmt.Errorf("a Debian release codename is required")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, db.Source, nil)
	if e != nil {
		return db, e
	}
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("advisory redirects are not accepted") }}
	resp, e := client.Do(req)
	if e != nil {
		return db, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return db, fmt.Errorf("official Debian tracker returned HTTP %d", resp.StatusCode)
	}
	if modified, e := http.ParseTime(resp.Header.Get("Last-Modified")); e == nil {
		db.SourceUpdatedAt = &modified
	}
	return debianReader(ctx, io.LimitReader(resp.Body, (128<<20)+1), release, db)
}

func DebianData(ctx context.Context, raw []byte, release string, db Database) (Database, error) {
	return debianReader(ctx, bytes.NewReader(raw), release, db)
}
func debianReader(ctx context.Context, reader io.Reader, release string, db Database) (Database, error) {
	decoder := json.NewDecoder(reader)
	first, e := decoder.Token()
	if e != nil || first != json.Delim('{') {
		return db, fmt.Errorf("invalid Debian tracker object")
	}
	found := false
	seen := map[string]bool{}
	for decoder.More() {
		if e := ctx.Err(); e != nil {
			return db, e
		}
		token, e := decoder.Token()
		if e != nil {
			return db, fmt.Errorf("invalid Debian package key")
		}
		pkg, ok := token.(string)
		if !ok || seen[pkg] {
			return db, fmt.Errorf("duplicate or invalid Debian source package")
		}
		seen[pkg] = true
		var records map[string]struct {
			Releases map[string]struct {
				Status  string `json:"status"`
				Fixed   string `json:"fixed_version"`
				Urgency string `json:"urgency"`
			} `json:"releases"`
		}
		if e := decoder.Decode(&records); e != nil {
			return db, fmt.Errorf("invalid Debian tracker package data")
		}
		if decoder.InputOffset() > 128<<20 {
			return db, fmt.Errorf("official tracker exceeds the 128MiB download budget")
		}
		for id, record := range records {
			if e := ctx.Err(); e != nil {
				return db, e
			}
			r, ok := record.Releases[release]
			if !ok {
				continue
			}
			found = true
			if r.Fixed == "0" {
				continue
			}
			if r.Status != "open" && r.Status != "resolved" && r.Status != "undetermined" {
				return db, fmt.Errorf("unsupported Debian advisory status for %s/%s", pkg, id)
			}
			if r.Status == "resolved" && r.Fixed == "" {
				return db, fmt.Errorf("resolved Debian advisory lacks a fixed version")
			}
			severity := "medium"
			switch strings.TrimSuffix(r.Urgency, "**") {
			case "high":
				severity = "high"
			case "low":
				severity = "low"
			case "unimportant":
				severity = "informational"
			}
			db.Records = append(db.Records, Record{ID: id, Distribution: "debian:" + release, Package: pkg, SourcePackage: true, Fixed: r.Fixed, Severity: severity, Uncertain: r.Status == "undetermined"})
			if len(db.Records) > 200000 {
				return db, fmt.Errorf("advisory record budget exceeded")
			}
		}
	}
	if _, e = decoder.Token(); e != nil {
		return db, fmt.Errorf("truncated Debian tracker object")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return db, fmt.Errorf("trailing Debian tracker data")
	}
	if !found {
		return db, fmt.Errorf("Debian tracker has no data for release %q", release)
	}
	slices.SortFunc(db.Records, func(a, b Record) int { return strings.Compare(a.Package+":"+a.ID, b.Package+":"+b.ID) })
	encoded, e := json.Marshal(db)
	if e != nil {
		return db, e
	}
	return Decode(encoded)
}
