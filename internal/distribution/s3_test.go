package distribution

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

func TestS3StorePathStyleConditionalUploadsAndPrivateVerification(t *testing.T) {
	t.Setenv("ASC_S3_ACCESS_KEY_ID", "test-access")
	t.Setenv("ASC_S3_SECRET_ACCESS_KEY", "test-secret")
	t.Setenv("ASC_S3_SESSION_TOKEN", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	type object struct {
		body, sha, contentType string
	}
	var mu sync.Mutex
	objects := map[string]object{}
	var operations []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !strings.HasPrefix(request.URL.Path, "/bucket/") {
			t.Errorf("path = %q", request.URL.Path)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.Header.Get("Authorization") == "" && request.Method != http.MethodGet {
			t.Error("signed API request omitted Authorization")
		}
		key := strings.TrimPrefix(request.URL.Path, "/bucket/")
		mu.Lock()
		defer mu.Unlock()
		switch request.Method {
		case http.MethodHead:
			operations = append(operations, "head:"+key)
			stored, ok := objects[key]
			if !ok {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			writer.Header().Set("Content-Length", strconv.Itoa(len(stored.body)))
			writer.Header().Set("Content-Type", stored.contentType)
			writer.Header().Set("x-amz-meta-asc-sha256", stored.sha)
			writer.WriteHeader(http.StatusOK)
		case http.MethodPut:
			operations = append(operations, "put:"+key)
			if request.Header.Get("If-None-Match") != "*" {
				t.Errorf("If-None-Match = %q", request.Header.Get("If-None-Match"))
			}
			body, _ := io.ReadAll(request.Body)
			objects[key] = object{body: string(body), sha: request.Header.Get("x-amz-meta-asc-sha256"), contentType: request.Header.Get("Content-Type")}
			writer.WriteHeader(http.StatusOK)
		case http.MethodGet:
			operations = append(operations, "get:"+key)
			stored, ok := objects[key]
			if !ok {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			writer.Header().Set("Content-Type", stored.contentType)
			writer.Header().Set("Content-Length", strconv.Itoa(len(stored.body)))
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(stored.body))
		default:
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	store, credentialExpiry, err := NewS3Store(context.Background(), S3StoreConfig{
		Endpoint: server.URL, Region: "auto", Bucket: "bucket", AddressingStyle: "path", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewS3Store() error = %v", err)
	}
	if !credentialExpiry.IsZero() {
		t.Fatalf("static credential expiry = %v", credentialExpiry)
	}
	ipa := []byte("ipa")
	receipt, sensitive, err := Publish(context.Background(), bytes.NewReader(ipa), minimalDescriptor(ipa), PublishOptions{
		Store: store, Verifier: NewHTTPVerifier(server.Client(), 5*time.Second), Bucket: "bucket", Prefix: "channel", Access: AccessPrivate,
		URLTTL: time.Hour, DownloadGrace: time.Minute, RandomID: func() (string, error) { return "link", nil },
	})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if !receipt.Verified || strings.Contains(receipt.InstallURL, "test-secret") || !strings.Contains(sensitive.InstallURL, "X-Amz-") {
		t.Fatalf("unexpected receipt/links: %#v %#v", receipt, sensitive)
	}
	for _, link := range []struct {
		name     string
		rawURL   string
		deadline time.Time
	}{
		{name: "install", rawURL: sensitive.InstallURL, deadline: *receipt.ExpiresAt},
		{name: "manifest", rawURL: sensitive.ManifestURL, deadline: receipt.ExpiresAt.Add(time.Minute)},
		{name: "artifact", rawURL: sensitive.ArtifactURL, deadline: receipt.ExpiresAt.Add(time.Minute)},
	} {
		if err := privateSignatureWithinDeadline(link.rawURL, link.deadline); err != nil {
			t.Fatalf("%s signature deadline: %v", link.name, err)
		}
	}
	wantTail := []string{
		"head:channel/objects/sha256/" + sha256Hex(ipa) + ".ipa",
		"put:channel/objects/sha256/" + sha256Hex(ipa) + ".ipa",
		"get:channel/objects/sha256/" + sha256Hex(ipa) + ".ipa",
		"head:channel/links/link/manifest.plist", "put:channel/links/link/manifest.plist", "get:channel/links/link/manifest.plist",
		"head:channel/links/link/index.html", "put:channel/links/link/index.html", "get:channel/links/link/index.html",
	}
	if strings.Join(operations, "\n") != strings.Join(wantTail, "\n") {
		t.Fatalf("operations = %#v, want %#v", operations, wantTail)
	}
}

func TestS3StoreDefaultClientHonorsAWSCABundle(t *testing.T) {
	t.Setenv("ASC_S3_ACCESS_KEY_ID", "test-access")
	t.Setenv("ASC_S3_SECRET_ACCESS_KEY", "test-secret")
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		switch request.Method {
		case http.MethodHead:
			writer.WriteHeader(http.StatusNotFound)
		case http.MethodPut:
			writer.WriteHeader(http.StatusOK)
		default:
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CA_BUNDLE", caPath)
	store, _, err := NewS3Store(context.Background(), S3StoreConfig{Endpoint: server.URL, Region: "auto", Bucket: "bucket", AddressingStyle: "path"})
	if err != nil {
		t.Fatalf("NewS3Store() error = %v", err)
	}
	input := PutObject{Key: "app.ipa", Body: strings.NewReader("ipa"), SHA256: sha256Hex([]byte("ipa")), SizeBytes: 3, ContentType: ContentTypeIPA}
	if _, err := store.Ensure(context.Background(), input); err != nil {
		t.Fatalf("Ensure() with AWS_CA_BUNDLE error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want HEAD and PUT only", requests)
	}
}

func TestS3StoreDefaultClientRefuses307And308WithoutForwardingCredentials(t *testing.T) {
	for _, redirectStatus := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(strconv.Itoa(redirectStatus), func(t *testing.T) {
			t.Setenv("ASC_S3_ACCESS_KEY_ID", "test-access")
			t.Setenv("ASC_S3_SECRET_ACCESS_KEY", "test-secret")
			targetRequests := 0
			target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				targetRequests++
				if request.Header.Get("Authorization") != "" || request.Header.Get("X-Amz-Security-Token") != "" {
					t.Errorf("redirect target received credentials")
				}
				writer.WriteHeader(http.StatusOK)
			}))
			defer target.Close()
			origin := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Location", target.URL+"/stolen")
				writer.WriteHeader(redirectStatus)
			}))
			defer origin.Close()
			caPath := filepath.Join(t.TempDir(), "ca.pem")
			var certificate []byte
			for _, server := range []*httptest.Server{origin, target} {
				certificate = append(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})...)
			}
			if err := os.WriteFile(caPath, certificate, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("AWS_CA_BUNDLE", caPath)
			store, _, err := NewS3Store(context.Background(), S3StoreConfig{Endpoint: origin.URL, Region: "auto", Bucket: "bucket", AddressingStyle: "path"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.Ensure(context.Background(), PutObject{Key: "app.ipa", Body: strings.NewReader("ipa"), SHA256: sha256Hex([]byte("ipa")), SizeBytes: 3, ContentType: ContentTypeIPA})
			if err == nil {
				t.Fatal("expected redirect response to fail")
			}
			if targetRequests != 0 {
				t.Fatalf("redirect target requests = %d, want 0", targetRequests)
			}
		})
	}
}

func TestStorageErrorsNeverEchoSignedQueryOrSessionMaterial(t *testing.T) {
	err := sanitizedStorageError("put object", "safe/key", errors.New("https://host/key?X-Amz-Signature=secret&X-Amz-Security-Token=session"))
	if text := err.Error(); strings.Contains(text, "secret") || strings.Contains(text, "session") || strings.Contains(text, "X-Amz") {
		t.Fatalf("sanitized error leaked bearer material: %q", text)
	}
}

func TestProviderControlledDiagnosticsNeverEchoMetadataOrAPICode(t *testing.T) {
	secret := "X-Amz-Security-Token=secret\x1b[31m"
	_, err := reconcileStoredObject(
		PutObject{Key: "safe/key", SHA256: "expected", SizeBytes: 1, ContentType: ContentTypeIPA},
		StoredObject{Key: "safe/key", SHA256: secret, SizeBytes: 2, ContentType: secret},
	)
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("collision diagnostic leaked provider data: %q", err)
	}
	apiErr := sanitizedStorageError("head object", "safe/key", &maliciousAPIError{code: secret})
	if strings.Contains(apiErr.Error(), "secret") || strings.Contains(apiErr.Error(), "\x1b") {
		t.Fatalf("API diagnostic leaked provider code: %q", apiErr)
	}
}

func TestS3EnsureReconcilesAmbiguousPutFailure(t *testing.T) {
	client := &ambiguousPutClient{}
	store := &S3Store{client: client, bucket: "bucket"}
	input := PutObject{Key: "app.ipa", Body: strings.NewReader("ipa"), SHA256: sha256Hex([]byte("ipa")), SizeBytes: 3, ContentType: ContentTypeIPA}
	got, err := store.Ensure(context.Background(), input)
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if got.Status != "reused" || client.headCalls != 2 {
		t.Fatalf("object=%#v headCalls=%d", got, client.headCalls)
	}
}

func TestS3EnsureReconcilesAfterPutContextExpires(t *testing.T) {
	client := &expiredPutClient{}
	contextCalls := 0
	store := &S3Store{
		client: client,
		bucket: "bucket",
		requestContext: func(parent context.Context) (context.Context, context.CancelFunc) {
			contextCalls++
			requestCtx, cancel := context.WithCancel(parent)
			if contextCalls == 2 {
				cancel()
				return requestCtx, func() {}
			}
			return requestCtx, cancel
		},
	}
	input := PutObject{Key: "app.ipa", Body: strings.NewReader("ipa"), SHA256: sha256Hex([]byte("ipa")), SizeBytes: 3, ContentType: ContentTypeIPA}

	got, err := store.Ensure(context.Background(), input)
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if got.Status != "reused" || client.headCalls != 2 || contextCalls != 3 {
		t.Fatalf("object=%#v headCalls=%d contextCalls=%d", got, client.headCalls, contextCalls)
	}
}

func TestS3ReplaceCorruptUsesFreshHeadAndConditionalPut(t *testing.T) {
	body := []byte("expected")
	client := &conditionalReplaceClient{
		object: StoredObject{
			Key: "objects/app.ipa", SHA256: sha256Hex(body), SizeBytes: int64(len(body)),
			ContentType: ContentTypeIPA, entityTag: `"poisoned-generation"`,
		},
	}
	store := &S3Store{client: client, bucket: "bucket"}

	replaced, err := store.ReplaceCorrupt(context.Background(), PutObject{
		Key: "objects/app.ipa", Body: bytes.NewReader(body), SHA256: sha256Hex(body),
		SizeBytes: int64(len(body)), ContentType: ContentTypeIPA,
	})
	if err != nil {
		t.Fatalf("ReplaceCorrupt() error = %v", err)
	}
	if client.ifMatch != `"poisoned-generation"` {
		t.Fatalf("conditional If-Match = %q", client.ifMatch)
	}
	if !bytes.Equal(client.body, body) || replaced.Status != "replaced" {
		t.Fatalf("replacement body=%q object=%#v", client.body, replaced)
	}
}

type conditionalReplaceClient struct {
	object  StoredObject
	ifMatch string
	body    []byte
}

func (client *conditionalReplaceClient) HeadObject(context.Context, *awss3.HeadObjectInput, ...func(*awss3.Options)) (*awss3.HeadObjectOutput, error) {
	return &awss3.HeadObjectOutput{
		ContentLength: aws.Int64(client.object.SizeBytes),
		ContentType:   aws.String(client.object.ContentType),
		ETag:          aws.String(client.object.entityTag),
		Metadata:      map[string]string{objectSHA256MetadataKey: client.object.SHA256},
	}, nil
}

func (client *conditionalReplaceClient) PutObject(_ context.Context, input *awss3.PutObjectInput, _ ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	client.ifMatch = aws.ToString(input.IfMatch)
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	client.body = body
	return &awss3.PutObjectOutput{}, nil
}

type ambiguousPutClient struct{ headCalls int }

func (client *ambiguousPutClient) HeadObject(context.Context, *awss3.HeadObjectInput, ...func(*awss3.Options)) (*awss3.HeadObjectOutput, error) {
	client.headCalls++
	if client.headCalls == 1 {
		return nil, &notFoundAPIError{}
	}
	return &awss3.HeadObjectOutput{ContentLength: aws.Int64(3), ContentType: aws.String(ContentTypeIPA), Metadata: map[string]string{objectSHA256MetadataKey: sha256Hex([]byte("ipa"))}}, nil
}

func (*ambiguousPutClient) PutObject(context.Context, *awss3.PutObjectInput, ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	return nil, errors.New("connection reset after server accepted object")
}

type expiredPutClient struct{ headCalls int }

func (client *expiredPutClient) HeadObject(ctx context.Context, _ *awss3.HeadObjectInput, _ ...func(*awss3.Options)) (*awss3.HeadObjectOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client.headCalls++
	if client.headCalls == 1 {
		return nil, &notFoundAPIError{}
	}
	return &awss3.HeadObjectOutput{ContentLength: aws.Int64(3), ContentType: aws.String(ContentTypeIPA), Metadata: map[string]string{objectSHA256MetadataKey: sha256Hex([]byte("ipa"))}}, nil
}

func (*expiredPutClient) PutObject(ctx context.Context, _ *awss3.PutObjectInput, _ ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("expected canceled PUT context")
}

type notFoundAPIError struct{}

func (*notFoundAPIError) Error() string                 { return "not found" }
func (*notFoundAPIError) ErrorCode() string             { return "NotFound" }
func (*notFoundAPIError) ErrorMessage() string          { return "not found" }
func (*notFoundAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

type maliciousAPIError struct{ code string }

func (err *maliciousAPIError) Error() string             { return err.code }
func (err *maliciousAPIError) ErrorCode() string         { return err.code }
func (err *maliciousAPIError) ErrorMessage() string      { return err.code }
func (*maliciousAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }
