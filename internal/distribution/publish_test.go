package distribution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLoadPreparedBundleValidatesArtifact(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	ipa := []byte("ipa bytes")
	digest := sha256.Sum256(ipa)
	certificateFingerprint := strings.Repeat("a", 64)
	descriptor := `{"schemaVersion":"1","platform":"IOS","distributionMethod":"release-testing","app":{"bundleId":"com.example.app","title":"Example","version":"1.2","buildNumber":"3"},"artifact":{"relativePath":"payload/app.ipa","sha256":"` + hex.EncodeToString(digest[:]) + `","sizeBytes":9},"signing":{"profileClass":"ad-hoc","profileUuid":"uuid","teamId":"TEAM","expiresAt":"2035-01-01T00:00:00Z","deviceCount":1,"deviceSetSha256":"` + strings.Repeat("b", 64) + `","profileCertificateSha256Fingerprints":["` + certificateFingerprint + `"],"profileIntegrityVerification":{"status":"verified"},"profileTrustVerification":{"status":"verified"},"codeSignatureVerification":{"status":"verified","scope":"complete-main-app-code-resources-entitlements-and-profile-certificate-binding","signerCertificateSha256Fingerprints":["` + certificateFingerprint + `"]}}}`
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), []byte(descriptor), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload", "app.ipa"), ipa, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadPreparedBundle(dir)
	if err != nil {
		t.Fatalf("LoadPreparedBundle() error = %v", err)
	}
	defer got.IPA.Close()
	if got.Descriptor.App.BundleID != "com.example.app" || got.IPASHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("unexpected bundle: %#v", got)
	}

	if err := os.WriteFile(filepath.Join(dir, "payload", "app.ipa"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPreparedBundle(dir); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("error = %v, want early size mismatch", err)
	}
}

func TestPreparedSigningRejectsConflictingFingerprintAlias(t *testing.T) {
	var descriptor PreparedDescriptor
	err := json.Unmarshal([]byte(`{"signing":{"profileCertificateSha256Fingerprints":["new"],"certificateSha256Fingerprints":["old"]}}`), &descriptor)
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("error = %v, want conflict", err)
	}
}

func TestValidateDescriptorRejectsUnsafePresentationText(t *testing.T) {
	descriptor := minimalDescriptor([]byte("ipa"))
	descriptor.App.Title = "Trusted\u202eexe"
	if err := validateDescriptor(descriptor); err == nil || !strings.Contains(err.Error(), "bidi") {
		t.Fatalf("error = %v, want bidi rejection", err)
	}
}

func TestValidateDescriptorRequiresAllVerificationsAndExactFullScope(t *testing.T) {
	for _, field := range []string{"integrity", "trust", "code", "scope"} {
		t.Run(field, func(t *testing.T) {
			descriptor := minimalDescriptor([]byte("ipa"))
			switch field {
			case "integrity":
				descriptor.Signing.ProfileIntegrityVerification.Status = ""
			case "trust":
				descriptor.Signing.ProfileTrustVerification.Status = "not-verified"
			case "code":
				descriptor.Signing.CodeSignatureVerification.Status = "unknown"
			case "scope":
				descriptor.Signing.CodeSignatureVerification.Scope = "main-executable-and-profile-certificate-binding"
			}
			if err := validateDescriptor(descriptor); err == nil || (!strings.Contains(err.Error(), "must be verified") && !strings.Contains(err.Error(), "scope must be")) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestValidateDescriptorRequiresSignerFingerprintBoundToProfile(t *testing.T) {
	for name, mutate := range map[string]func(*PreparedDescriptor){
		"missing": func(descriptor *PreparedDescriptor) {
			descriptor.Signing.CodeSignatureVerification.SignerCertificateSHA256Fingerprints = nil
		},
		"malformed": func(descriptor *PreparedDescriptor) {
			descriptor.Signing.CodeSignatureVerification.SignerCertificateSHA256Fingerprints = []string{"not-a-digest"}
		},
		"not in profile": func(descriptor *PreparedDescriptor) {
			descriptor.Signing.CodeSignatureVerification.SignerCertificateSHA256Fingerprints = []string{strings.Repeat("c", 64)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			descriptor := minimalDescriptor([]byte("ipa"))
			mutate(&descriptor)
			if err := validateDescriptor(descriptor); err == nil {
				t.Fatal("expected signer fingerprint validation error")
			}
		})
	}
}

func TestReceiptSigningBindsSignerFingerprintEvidence(t *testing.T) {
	descriptor := minimalDescriptor([]byte("ipa"))
	receipt := receiptSigningFromPrepared(descriptor.Signing)
	if !receipt.MatchesPrepared(descriptor.Signing) {
		t.Fatal("fresh receipt signing facts did not match prepared descriptor")
	}
	receipt.CodeSignatureVerification.SignerCertificateSHA256Fingerprints = []string{strings.Repeat("c", 64)}
	if receipt.MatchesPrepared(descriptor.Signing) {
		t.Fatal("tampered signer fingerprint evidence matched prepared descriptor")
	}
}

func TestPublishOrdersObjectsAndRedactsInstallURL(t *testing.T) {
	store := &fakeObjectStore{}
	verifier := &recordingVerifier{}
	descriptor := minimalDescriptor([]byte("ipa"))
	descriptor.App.Version = "1.2"
	descriptor.App.BuildNumber = "3"
	result, sensitive, err := Publish(context.Background(), bytes.NewReader([]byte("ipa")), descriptor, PublishOptions{
		Store: store, Verifier: verifier, Bucket: "bucket", Prefix: "team/app", Access: AccessPrivate,
		URLTTL: time.Hour, DownloadGrace: 10 * time.Minute, Now: func() time.Time { return time.Unix(1000, 0).UTC() },
		RandomID: func() (string, error) { return "link-id", nil },
	})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	wantOrder := []string{
		"put:team/app/objects/sha256/78324857e8d9bfa749dc301271df54a6572de9f4c3df8a9507cfa7b7d2b25f8e.ipa",
		"put:team/app/links/link-id/manifest.plist",
		"put:team/app/links/link-id/index.html",
	}
	if !reflect.DeepEqual(store.calls, wantOrder) {
		t.Fatalf("calls = %#v, want %#v", store.calls, wantOrder)
	}
	if strings.Contains(result.InstallURL, "X-Amz-Signature") || !strings.Contains(result.InstallURL, "REDACTED") {
		t.Fatalf("result URL was not redacted: %q", result.InstallURL)
	}
	if !strings.Contains(sensitive.InstallURL, "X-Amz-Signature") {
		t.Fatalf("sensitive URL missing signature: %q", sensitive.InstallURL)
	}
	manifest := string(store.bodies["team/app/links/link-id/manifest.plist"])
	if !strings.Contains(manifest, "itms-services") && !strings.Contains(manifest, "software-package") {
		t.Fatalf("unexpected manifest: %s", manifest)
	}
	page := string(store.bodies["team/app/links/link-id/index.html"])
	if !strings.Contains(page, "itms-services://?action=download-manifest") || strings.Contains(page, "<script") {
		t.Fatalf("unexpected install page: %s", page)
	}
	if len(verifier.urls) != 3 {
		t.Fatalf("verified %d URLs, want 3", len(verifier.urls))
	}
}

func TestPublishRejectsProfileExpiringBeforePrivateLinkWithoutWriting(t *testing.T) {
	store := &fakeObjectStore{}
	now := time.Now().UTC().Truncate(time.Second)
	descriptor := minimalDescriptor([]byte("ipa"))
	descriptor.Signing.ExpiresAt = now.Add(70 * time.Minute).Format(time.RFC3339)
	_, _, err := Publish(context.Background(), bytes.NewReader([]byte("ipa")), descriptor, PublishOptions{
		Store: store, Verifier: &recordingVerifier{}, Bucket: "bucket", Prefix: "app", Access: AccessPrivate,
		URLTTL: time.Hour, DownloadGrace: 10 * time.Minute, Now: func() time.Time { return now },
	})
	if err == nil || !strings.Contains(err.Error(), "profile expires too soon") {
		t.Fatalf("error = %v", err)
	}
	if len(store.calls) != 0 {
		t.Fatalf("store calls = %v, want none", store.calls)
	}
}

func TestPublishRejectsUnsafeBucketBeforeWriting(t *testing.T) {
	store := &fakeObjectStore{}
	_, _, err := Publish(context.Background(), bytes.NewReader([]byte("ipa")), minimalDescriptor([]byte("ipa")), PublishOptions{
		Store: store, Verifier: &recordingVerifier{}, Bucket: "bucket\u200bhidden", Prefix: "app", Access: AccessPrivate,
		URLTTL: time.Hour, DownloadGrace: time.Minute,
	})
	if err == nil || !strings.Contains(err.Error(), "bucket") {
		t.Fatalf("Publish() error = %v, want unsafe bucket rejection", err)
	}
	if len(store.calls) != 0 {
		t.Fatalf("store calls = %v, want none", store.calls)
	}
}

func TestPresignedLifetimesShrinkAsPublicationWorkElapses(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := &delayedPresignStore{fakeObjectStore: fakeObjectStore{}, now: now}
	descriptor := minimalDescriptor([]byte("ipa"))
	descriptor.Signing.ExpiresAt = now.Add(48 * time.Hour).Format(time.RFC3339)
	_, _, err := Publish(context.Background(), bytes.NewReader([]byte("ipa")), descriptor, PublishOptions{
		Store: store, Verifier: &recordingVerifier{}, Bucket: "bucket", Prefix: "app", Access: AccessPrivate,
		URLTTL: time.Hour, DownloadGrace: 10 * time.Minute, Now: func() time.Time { return store.now }, RandomID: func() (string, error) { return "id", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{70 * time.Minute, 69 * time.Minute, 48 * time.Minute}
	if !reflect.DeepEqual(store.ttls, want) {
		t.Fatalf("presigned TTLs = %v, want %v", store.ttls, want)
	}
}

func TestPublishReusesExactObjectAndRejectsConflict(t *testing.T) {
	ipa := []byte("ipa")
	key := "prefix/objects/sha256/" + sha256Hex(ipa) + ".ipa"
	store := &fakeObjectStore{objects: map[string]StoredObject{
		key: {Key: key, SHA256: sha256Hex(ipa), SizeBytes: 3, ContentType: ContentTypeIPA},
	}}
	_, _, err := Publish(context.Background(), bytes.NewReader(ipa), minimalDescriptor(ipa), PublishOptions{
		Store: store, Verifier: &recordingVerifier{}, Bucket: "bucket", Prefix: "prefix", Access: AccessPrivate,
		URLTTL: time.Hour, DownloadGrace: time.Minute, RandomID: func() (string, error) { return "id", nil },
	})
	if err != nil {
		t.Fatalf("exact reuse error = %v", err)
	}
	if len(store.calls) == 0 || store.calls[0] != "reuse:"+key {
		t.Fatalf("calls = %#v", store.calls)
	}

	store = &fakeObjectStore{objects: map[string]StoredObject{key: {Key: key, SHA256: "wrong", SizeBytes: 3, ContentType: ContentTypeIPA}}}
	_, _, err = Publish(context.Background(), bytes.NewReader(ipa), minimalDescriptor(ipa), PublishOptions{
		Store: store, Verifier: &recordingVerifier{}, Bucket: "bucket", Prefix: "prefix", Access: AccessPrivate,
		URLTTL: time.Hour, DownloadGrace: time.Minute, RandomID: func() (string, error) { return "id", nil },
	})
	if err == nil || !strings.Contains(err.Error(), "immutable object conflict") {
		t.Fatalf("error = %v, want immutable conflict", err)
	}
}

func TestValidateEndpointRequiresUnadornedHTTPS(t *testing.T) {
	for _, raw := range []string{"http://objects.example.com", "https://user@example.com", "https://objects.example.com/path", "https://objects.example.com?x=1", "https://objects.example.com/#frag"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ValidateEndpoint(raw); err == nil {
				t.Fatalf("ValidateEndpoint(%q) unexpectedly succeeded", raw)
			}
		})
	}
	got, err := ValidateEndpoint("https://objects.example.com")
	if err != nil || got.String() != "https://objects.example.com" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestPublicObjectURLPreservesBasePathWithoutDoubleEncoding(t *testing.T) {
	got, err := PublicObjectURL("https://downloads.example.com/team%20name/%E2%9C%93", "app path/100%.ipa")
	if err != nil {
		t.Fatal(err)
	}
	const want = "https://downloads.example.com/team%20name/%E2%9C%93/app%20path/100%25.ipa"
	if got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func TestBoundedLifetimesPreservesGraceWhenCredentialsExpireSooner(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	ttl, grace, err := boundedLifetimes(now, 24*time.Hour, time.Hour, now.Add(10*time.Hour), AccessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if grace != time.Hour || ttl != 8*time.Hour+59*time.Minute {
		t.Fatalf("ttl=%s grace=%s", ttl, grace)
	}
}

func TestReverifyRejectsTamperedSensitiveLinkBinding(t *testing.T) {
	receipt := PublishReceipt{
		SchemaVersion: "1", Access: AccessPrivate, DownloadEndpoint: "https://host", AddressingStyle: "virtual", Bucket: "",
		Artifact:   StoredObject{Key: "prefix/app.ipa", SHA256: "a", SizeBytes: 1, ContentType: ContentTypeIPA},
		Manifest:   StoredObject{Key: "prefix/manifest.plist", SHA256: "b", SizeBytes: 1, ContentType: ContentTypeManifest},
		Page:       StoredObject{Key: "prefix/index.html", SHA256: "c", SizeBytes: 1, ContentType: ContentTypeHTML},
		InstallURL: "https://host/prefix/index.html?REDACTED", DirectInstallURL: "itms-services://?action=download-manifest&url=REDACTED",
	}
	expires := time.Now().Add(time.Hour)
	receipt.ExpiresAt = &expires
	links := SensitiveLinks{SchemaVersion: "1", InstallURL: "https://host/prefix/index.html?secret=one", ManifestURL: "https://host/prefix/manifest.plist?secret=two", ArtifactURL: "https://host/prefix/app.ipa?secret=three", ExpiresAt: &expires}
	links.DirectInstallURL = "itms-services://?action=download-manifest&url=" + url.QueryEscape(links.ManifestURL)
	receipt.InstallURL = redactBearerURL(links.InstallURL)
	receipt.DirectInstallURL = redactDirectInstallURL(links.DirectInstallURL)
	markRecoveryFixtureVerified(&receipt)
	links.ManifestURL = "https://evil.example/other.plist?secret=tampered"
	if err := Reverify(context.Background(), &recordingVerifier{}, receipt, links, time.Now()); err == nil || !strings.Contains(err.Error(), "does not reference") {
		t.Fatalf("error = %v", err)
	}
}

func TestReverifyRejectsDifferentPrivateOriginWithExpectedObjectPath(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	receipt := PublishReceipt{
		SchemaVersion: "1", Access: AccessPrivate, DownloadEndpoint: "https://downloads.example.com", AddressingStyle: "path", Bucket: "bucket",
		Artifact:  StoredObject{Key: "prefix/app.ipa", SHA256: "a", SizeBytes: 1, ContentType: ContentTypeIPA},
		Manifest:  StoredObject{Key: "prefix/manifest.plist", SHA256: "b", SizeBytes: 1, ContentType: ContentTypeManifest},
		Page:      StoredObject{Key: "prefix/index.html", SHA256: "c", SizeBytes: 1, ContentType: ContentTypeHTML},
		ExpiresAt: &expires,
	}
	links := SensitiveLinks{
		SchemaVersion: "1", ExpiresAt: &expires,
		InstallURL:  "https://evil.example/bucket/prefix/index.html?X-Amz-Signature=one",
		ManifestURL: "https://evil.example/bucket/prefix/manifest.plist?X-Amz-Signature=two",
		ArtifactURL: "https://evil.example/bucket/prefix/app.ipa?X-Amz-Signature=three",
	}
	links.DirectInstallURL = "itms-services://?action=download-manifest&url=" + url.QueryEscape(links.ManifestURL)
	receipt.InstallURL = redactBearerURL(links.InstallURL)
	receipt.DirectInstallURL = redactDirectInstallURL(links.DirectInstallURL)
	markRecoveryFixtureVerified(&receipt)
	if err := Reverify(context.Background(), &recordingVerifier{}, receipt, links, time.Now()); err == nil || !strings.Contains(err.Error(), "download endpoint") {
		t.Fatalf("error = %v", err)
	}
}

func TestReverifyAcceptsBoundPrivatePathStyleLinks(t *testing.T) {
	signedAt := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)
	expires := signedAt.Add(time.Hour)
	receipt := PublishReceipt{
		SchemaVersion: "1", Access: AccessPrivate, DownloadEndpoint: "https://downloads.example.com", AddressingStyle: "path", Bucket: "bucket",
		Artifact:      StoredObject{Key: "prefix/app.ipa", SHA256: "a", SizeBytes: 1, ContentType: ContentTypeIPA},
		Manifest:      StoredObject{Key: "prefix/manifest.plist", SHA256: "b", SizeBytes: 1, ContentType: ContentTypeManifest},
		Page:          StoredObject{Key: "prefix/index.html", SHA256: "c", SizeBytes: 1, ContentType: ContentTypeHTML},
		DownloadGrace: "0s", ExpiresAt: &expires,
	}
	links := SensitiveLinks{
		SchemaVersion: "1", ExpiresAt: &expires,
		InstallURL:  privateSignatureFixture("/bucket/prefix/index.html", signedAt, time.Hour),
		ManifestURL: privateSignatureFixture("/bucket/prefix/manifest.plist", signedAt, time.Hour),
		ArtifactURL: privateSignatureFixture("/bucket/prefix/app.ipa", signedAt, time.Hour),
	}
	links.DirectInstallURL = "itms-services://?action=download-manifest&url=" + url.QueryEscape(links.ManifestURL)
	receipt.InstallURL = redactBearerURL(links.InstallURL)
	receipt.DirectInstallURL = redactDirectInstallURL(links.DirectInstallURL)
	receipt.Verified = true
	receipt.Signing.ProfileExpiresAt = expires.Add(time.Hour).Format(time.RFC3339)
	bindGeneratedRecoveryObjects(t, &receipt, links)
	verifier := &recordingVerifier{}
	if err := Reverify(context.Background(), verifier, receipt, links, signedAt.Add(time.Minute)); err != nil {
		t.Fatalf("Reverify() error = %v", err)
	}
	if len(verifier.urls) != 3 {
		t.Fatalf("verified URLs = %d, want 3", len(verifier.urls))
	}
}

func TestReverifyRejectsPrivateSignaturesOutlivingReceiptDeadlines(t *testing.T) {
	signedAt := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)
	pageDeadline := signedAt.Add(time.Hour)
	grace := 10 * time.Minute

	for _, target := range []string{"install", "manifest", "artifact"} {
		t.Run(target, func(t *testing.T) {
			receipt := PublishReceipt{
				SchemaVersion: "1", Access: AccessPrivate, DownloadEndpoint: "https://downloads.example.com", AddressingStyle: "path", Bucket: "bucket",
				DownloadGrace: grace.String(), ExpiresAt: &pageDeadline, Verified: true,
				Artifact: StoredObject{Key: "prefix/app.ipa", SHA256: "a", SizeBytes: 1, ContentType: ContentTypeIPA},
				Manifest: StoredObject{Key: "prefix/manifest.plist", SHA256: "b", SizeBytes: 1, ContentType: ContentTypeManifest},
				Page:     StoredObject{Key: "prefix/index.html", SHA256: "c", SizeBytes: 1, ContentType: ContentTypeHTML},
				Signing:  ReceiptSigning{ProfileExpiresAt: pageDeadline.Add(grace + time.Hour).Format(time.RFC3339)},
			}
			links := SensitiveLinks{
				SchemaVersion: "1", ExpiresAt: &pageDeadline,
				InstallURL:  privateSignatureFixture("/bucket/prefix/index.html", signedAt, time.Hour),
				ManifestURL: privateSignatureFixture("/bucket/prefix/manifest.plist", signedAt, time.Hour+grace),
				ArtifactURL: privateSignatureFixture("/bucket/prefix/app.ipa", signedAt, time.Hour+grace),
			}
			switch target {
			case "install":
				links.InstallURL = privateSignatureFixture("/bucket/prefix/index.html", signedAt, time.Hour+time.Second)
			case "manifest":
				links.ManifestURL = privateSignatureFixture("/bucket/prefix/manifest.plist", signedAt, time.Hour+grace+time.Second)
			case "artifact":
				links.ArtifactURL = privateSignatureFixture("/bucket/prefix/app.ipa", signedAt, time.Hour+grace+time.Second)
			}
			links.DirectInstallURL = "itms-services://?action=download-manifest&url=" + url.QueryEscape(links.ManifestURL)
			receipt.InstallURL = redactBearerURL(links.InstallURL)
			receipt.DirectInstallURL = redactDirectInstallURL(links.DirectInstallURL)
			bindGeneratedRecoveryObjects(t, &receipt, links)

			verifier := &recordingVerifier{}
			err := Reverify(context.Background(), verifier, receipt, links, signedAt.Add(time.Minute))
			if err == nil || !strings.Contains(err.Error(), "signed expiry exceeds") {
				t.Fatalf("Reverify() error = %v, want signed deadline rejection", err)
			}
			if len(verifier.urls) != 0 {
				t.Fatalf("live verifier calls = %d, want none", len(verifier.urls))
			}
		})
	}
}

func TestReverifyRequiresExactPublicBaseURL(t *testing.T) {
	receipt := PublishReceipt{
		SchemaVersion: "1", Access: AccessPublic, PublicBaseURL: "https://downloads.example.com/releases",
		Artifact: StoredObject{Key: "prefix/app.ipa", SHA256: "a", SizeBytes: 1, ContentType: ContentTypeIPA},
		Manifest: StoredObject{Key: "prefix/manifest.plist", SHA256: "b", SizeBytes: 1, ContentType: ContentTypeManifest},
		Page:     StoredObject{Key: "prefix/index.html", SHA256: "c", SizeBytes: 1, ContentType: ContentTypeHTML},
	}
	links := SensitiveLinks{
		SchemaVersion: "1",
		InstallURL:    "https://evil.example/releases/prefix/index.html",
		ManifestURL:   "https://evil.example/releases/prefix/manifest.plist",
		ArtifactURL:   "https://evil.example/releases/prefix/app.ipa",
	}
	links.DirectInstallURL = "itms-services://?action=download-manifest&url=" + url.QueryEscape(links.ManifestURL)
	receipt.InstallURL = links.InstallURL
	receipt.DirectInstallURL = redactDirectInstallURL(links.DirectInstallURL)
	markRecoveryFixtureVerified(&receipt)
	if err := Reverify(context.Background(), &recordingVerifier{}, receipt, links, time.Now()); err == nil || !strings.Contains(err.Error(), "public base") {
		t.Fatalf("error = %v", err)
	}
}

func markRecoveryFixtureVerified(receipt *PublishReceipt) {
	receipt.Verified = true
	receipt.Signing.ProfileExpiresAt = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
}

func bindGeneratedRecoveryObjects(t *testing.T, receipt *PublishReceipt, links SensitiveLinks) {
	t.Helper()
	manifest, err := makeManifest(receipt.App, links.ArtifactURL)
	if err != nil {
		t.Fatal(err)
	}
	page, err := makeInstallPage(receipt.App, links.DirectInstallURL)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(manifest)
	pageDigest := sha256.Sum256(page)
	receipt.Manifest.SHA256 = hex.EncodeToString(manifestDigest[:])
	receipt.Manifest.SizeBytes = int64(len(manifest))
	receipt.Manifest.ContentType = ContentTypeManifest
	receipt.Page.SHA256 = hex.EncodeToString(pageDigest[:])
	receipt.Page.SizeBytes = int64(len(page))
	receipt.Page.ContentType = ContentTypeHTML
}

func privateSignatureFixture(path string, signedAt time.Time, lifetime time.Duration) string {
	query := url.Values{}
	query.Set("X-Amz-Date", signedAt.UTC().Format("20060102T150405Z"))
	query.Set("X-Amz-Expires", strconv.FormatInt(int64(lifetime/time.Second), 10))
	query.Set("X-Amz-Signature", "fixture-signature")
	return (&url.URL{Scheme: "https", Host: "downloads.example.com", Path: path, RawQuery: query.Encode()}).String()
}

func TestVerifyURLRefusesRedirectAndUsesIPARange(t *testing.T) {
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Range") != "" {
			t.Fatalf("Range = %q, want full cryptographic verification", request.Header.Get("Range"))
		}
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"https://evil.example"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})}
	err := NewHTTPVerifier(client, time.Second).Verify(context.Background(), VerifyRequest{URL: "https://example.com/app.ipa?secret=yes", Kind: VerifyIPA, ContentType: ContentTypeIPA, SizeBytes: 1})
	if err == nil || !strings.Contains(err.Error(), "redirect") || strings.Contains(err.Error(), "secret=yes") {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifierProviderHeadersNeverReachDiagnostic(t *testing.T) {
	secret := "X-Amz-Security-Token=secret\x1b[31m"
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{secret}}, Body: io.NopCloser(strings.NewReader("x")), Request: request}, nil
	})}
	err := NewHTTPVerifier(client, time.Second).Verify(context.Background(), VerifyRequest{URL: "https://example.com/app.ipa", Kind: VerifyIPA, ContentType: ContentTypeIPA, SizeBytes: 1})
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("diagnostic leaked provider header: %q", err)
	}
}

type fakeObjectStore struct {
	objects map[string]StoredObject
	bodies  map[string][]byte
	calls   []string
}

type delayedPresignStore struct {
	fakeObjectStore
	now  time.Time
	ttls []time.Duration
}

func (store *delayedPresignStore) PresignGet(_ context.Context, key string, ttl time.Duration) (string, error) {
	store.ttls = append(store.ttls, ttl)
	store.now = store.now.Add(time.Minute)
	if strings.HasSuffix(key, "manifest.plist") {
		store.now = store.now.Add(10 * time.Minute)
	}
	return (&url.URL{Scheme: "https", Host: "download.example.com", Path: "/" + key, RawQuery: "X-Amz-Signature=secret"}).String(), nil
}

func (f *fakeObjectStore) Ensure(_ context.Context, input PutObject) (StoredObject, error) {
	if f.objects == nil {
		f.objects = map[string]StoredObject{}
	}
	if f.bodies == nil {
		f.bodies = map[string][]byte{}
	}
	if existing, ok := f.objects[input.Key]; ok {
		if existing.SHA256 != input.SHA256 || existing.SizeBytes != input.SizeBytes || existing.ContentType != input.ContentType {
			return StoredObject{}, errors.New("immutable object conflict")
		}
		existing.Status = "reused"
		f.calls = append(f.calls, "reuse:"+input.Key)
		return existing, nil
	}
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return StoredObject{}, err
	}
	object := StoredObject{Key: input.Key, SHA256: input.SHA256, SizeBytes: input.SizeBytes, ContentType: input.ContentType, Status: "uploaded"}
	f.objects[input.Key] = object
	f.calls = append(f.calls, "put:"+input.Key)
	// Tests inspect generated bodies without expanding the public receipt type.
	f.objects[input.Key] = object
	f.bodies[input.Key] = body
	return object, nil
}

func (f *fakeObjectStore) PresignGet(_ context.Context, key string, _ time.Duration) (string, error) {
	return (&url.URL{Scheme: "https", Host: "download.example.com", Path: "/" + key, RawQuery: "X-Amz-Signature=secret"}).String(), nil
}

type recordingVerifier struct{ urls []string }

func (v *recordingVerifier) Verify(_ context.Context, request VerifyRequest) error {
	v.urls = append(v.urls, request.URL)
	return nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func minimalDescriptor(ipa []byte) PreparedDescriptor {
	return PreparedDescriptor{
		SchemaVersion: "1", Platform: "IOS", DistributionMethod: "release-testing",
		App:      PreparedApp{BundleID: "com.example.app", Title: "Example", Version: "1", BuildNumber: "1"},
		Artifact: PreparedArtifact{RelativePath: "payload/app.ipa", SHA256: sha256Hex(ipa), SizeBytes: int64(len(ipa))},
		Signing: PreparedSigning{
			ProfileClass: "ad-hoc", ProfileUUID: "uuid", TeamID: "TEAM", ExpiresAt: "2035-01-01T00:00:00Z", DeviceCount: 1,
			DeviceSetSHA256: strings.Repeat("b", 64), ProfileCertificateSHA256Fingerprints: []string{strings.Repeat("a", 64)},
			ProfileIntegrityVerification: PreparedCodeSignatureVerification{Status: "verified"}, ProfileTrustVerification: PreparedCodeSignatureVerification{Status: "verified"},
			CodeSignatureVerification: PreparedCodeSignatureVerification{Status: "verified", Scope: "complete-main-app-code-resources-entitlements-and-profile-certificate-binding", SignerCertificateSHA256Fingerprints: []string{strings.Repeat("a", 64)}},
		},
	}
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

var _ = errors.Is
