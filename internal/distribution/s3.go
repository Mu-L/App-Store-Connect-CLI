package distribution

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	transporthttp "github.com/aws/smithy-go/transport/http"
)

const objectSHA256MetadataKey = "asc-sha256"

type S3StoreConfig struct {
	Endpoint         string
	DownloadEndpoint string
	Region           string
	Bucket           string
	AddressingStyle  string
	HTTPClient       *http.Client
}

type s3API interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type s3Presigner interface {
	PresignGetObject(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

type S3Store struct {
	client           s3API
	presigner        s3Presigner
	bucket           string
	credentialSource string
}

func NewS3Store(ctx context.Context, options S3StoreConfig) (*S3Store, time.Time, error) {
	endpoint, err := ValidateEndpoint(options.Endpoint)
	if err != nil {
		return nil, time.Time{}, err
	}
	downloadEndpoint := endpoint
	if strings.TrimSpace(options.DownloadEndpoint) != "" {
		downloadEndpoint, err = ValidateEndpoint(options.DownloadEndpoint)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("download endpoint: %w", err)
		}
	}
	if strings.TrimSpace(options.Region) == "" {
		return nil, time.Time{}, fmt.Errorf("region is required")
	}
	if err := ValidateBucket(options.Bucket); err != nil {
		return nil, time.Time{}, err
	}
	usePathStyle, err := addressingPathStyle(options.AddressingStyle)
	if err != nil {
		return nil, time.Time{}, err
	}

	var client aws.HTTPClient = awshttp.NewBuildableClient()
	if options.HTTPClient != nil {
		client = noRedirectClient(options.HTTPClient)
	}
	loadOptions := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(strings.TrimSpace(options.Region)),
		awsconfig.WithHTTPClient(client),
	}
	aliasProvider, configured, err := ascS3CredentialsFromEnvironment()
	if err != nil {
		return nil, time.Time{}, err
	}
	if configured {
		loadOptions = append(loadOptions, awsconfig.WithCredentialsProvider(aliasProvider))
	}
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("load S3 configuration failed")
	}
	if buildable, ok := awsConfig.HTTPClient.(*awshttp.BuildableClient); ok {
		awsConfig.HTTPClient = noRedirectRoundTripperClient(buildable.GetTransport())
	} else if configuredClient, ok := awsConfig.HTTPClient.(*http.Client); ok {
		awsConfig.HTTPClient = noRedirectClient(configuredClient)
	} else if awsConfig.HTTPClient == nil {
		awsConfig.HTTPClient = noRedirectRoundTripperClient(http.DefaultTransport)
	} else {
		return nil, time.Time{}, fmt.Errorf("configured S3 HTTP client cannot enforce the no-redirect policy")
	}
	resolvedCredentials, err := awsConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("resolve S3 credentials failed")
	}
	credentialLimit := time.Time{}
	if resolvedCredentials.CanExpire {
		credentialLimit = resolvedCredentials.Expires.UTC()
	}

	newClient := func(baseEndpoint string) *s3.Client {
		return s3.NewFromConfig(awsConfig, func(s3Options *s3.Options) {
			s3Options.BaseEndpoint = aws.String(baseEndpoint)
			s3Options.UsePathStyle = usePathStyle
			s3Options.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
			s3Options.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		})
	}
	uploadClient := newClient(endpoint.String())
	downloadClient := uploadClient
	if downloadEndpoint.String() != endpoint.String() {
		downloadClient = newClient(downloadEndpoint.String())
	}
	credentialSource := ""
	if configured {
		credentialSource = "asc-s3-environment"
	} else {
		credentialSource = categorizeCredentialSource(resolvedCredentials.Source)
	}
	return &S3Store{client: uploadClient, presigner: s3.NewPresignClient(downloadClient), bucket: strings.TrimSpace(options.Bucket), credentialSource: credentialSource}, credentialLimit, nil
}

func (store *S3Store) CredentialSource() string { return store.credentialSource }

func (store *S3Store) Ensure(ctx context.Context, input PutObject) (StoredObject, error) {
	existing, err := store.head(ctx, input.Key)
	if err == nil {
		return reconcileStoredObject(input, existing)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return StoredObject{}, err
	}
	digest, decodeErr := hex.DecodeString(input.SHA256)
	if decodeErr != nil || len(digest) != 32 {
		return StoredObject{}, fmt.Errorf("put object identity has invalid SHA-256")
	}
	_, err = store.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:         aws.String(store.bucket),
		Key:            aws.String(input.Key),
		Body:           input.Body,
		ContentLength:  aws.Int64(input.SizeBytes),
		ContentType:    aws.String(input.ContentType),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest)),
		IfNoneMatch:    aws.String("*"),
		Metadata:       map[string]string{objectSHA256MetadataKey: input.SHA256},
	})
	if err != nil {
		existing, headErr := store.head(ctx, input.Key)
		if headErr == nil {
			return reconcileStoredObject(input, existing)
		}
		if isPreconditionFailed(err) {
			return StoredObject{}, fmt.Errorf("reconcile concurrent object %q failed", input.Key)
		}
		return StoredObject{}, sanitizedStorageError("put object", input.Key, err)
	}
	return StoredObject{Key: input.Key, SHA256: input.SHA256, SizeBytes: input.SizeBytes, ContentType: input.ContentType, Status: "uploaded"}, nil
}

func (store *S3Store) PresignGet(ctx context.Context, key string, ttl time.Duration) (string, error) {
	request, err := store.presigner.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key)}, func(options *s3.PresignOptions) {
		options.Expires = ttl
	})
	if err != nil {
		return "", sanitizedStorageError("presign object", key, err)
	}
	return request.URL, nil
}

func (store *S3Store) head(ctx context.Context, key string) (StoredObject, error) {
	response, err := store.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(store.bucket), Key: aws.String(key)})
	if err != nil {
		if isNotFound(err) {
			return StoredObject{}, os.ErrNotExist
		}
		return StoredObject{}, sanitizedStorageError("head object", key, err)
	}
	sha := response.Metadata[objectSHA256MetadataKey]
	if sha == "" {
		sha = response.Metadata[strings.ToLower(objectSHA256MetadataKey)]
	}
	return StoredObject{Key: key, SHA256: strings.ToLower(sha), SizeBytes: aws.ToInt64(response.ContentLength), ContentType: aws.ToString(response.ContentType)}, nil
}

func reconcileStoredObject(input PutObject, existing StoredObject) (StoredObject, error) {
	if !strings.EqualFold(existing.SHA256, input.SHA256) || existing.SizeBytes != input.SizeBytes || existing.ContentType != input.ContentType {
		return StoredObject{}, fmt.Errorf("%w at %q: existing metadata does not match expected SHA-256, size, and content type", ErrImmutableObjectConflict, input.Key)
	}
	existing.Status = "reused"
	return existing, nil
}

func addressingPathStyle(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "path":
		return true, nil
	case "virtual":
		return false, nil
	default:
		return false, fmt.Errorf("addressing style must be path or virtual")
	}
}

func ascS3CredentialsFromEnvironment() (aws.CredentialsProvider, bool, error) {
	accessKey := strings.TrimSpace(os.Getenv("ASC_S3_ACCESS_KEY_ID"))
	secretKey := strings.TrimSpace(os.Getenv("ASC_S3_SECRET_ACCESS_KEY"))
	sessionToken := strings.TrimSpace(os.Getenv("ASC_S3_SESSION_TOKEN"))
	if accessKey == "" && secretKey == "" && sessionToken == "" {
		return nil, false, nil
	}
	if accessKey == "" || secretKey == "" {
		return nil, false, fmt.Errorf("ASC_S3_ACCESS_KEY_ID and ASC_S3_SECRET_ACCESS_KEY must be set together")
	}
	return credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken), true, nil
}

func noRedirectClient(source *http.Client) *http.Client {
	if source == nil {
		source = &http.Client{}
	}
	clone := *source
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &clone
}

func noRedirectRoundTripperClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func isNotFound(err error) bool {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch strings.ToLower(apiError.ErrorCode()) {
		case "notfound", "nosuchkey", "404":
			return true
		}
	}
	var responseError *transporthttp.ResponseError
	return errors.As(err, &responseError) && responseError.HTTPStatusCode() == http.StatusNotFound
}

func isPreconditionFailed(err error) bool {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch strings.ToLower(apiError.ErrorCode()) {
		case "preconditionfailed", "conditionalrequestconflict", "412":
			return true
		}
	}
	var responseError *transporthttp.ResponseError
	return errors.As(err, &responseError) && responseError.HTTPStatusCode() == http.StatusPreconditionFailed
}

func sanitizedStorageError(operation, key string, err error) error {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		return fmt.Errorf("%s %q failed: provider API error", operation, key)
	}
	var responseError *transporthttp.ResponseError
	if errors.As(err, &responseError) {
		return fmt.Errorf("%s %q failed: status=%d", operation, key, responseError.HTTPStatusCode())
	}
	return fmt.Errorf("%s %q failed", operation, key)
}

func categorizeCredentialSource(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "environment"), strings.Contains(lower, "envconfig"):
		return "aws-environment"
	case strings.Contains(lower, "shared"):
		return "shared-config"
	case strings.Contains(lower, "webidentity"):
		return "web-identity"
	case strings.Contains(lower, "ecs"), strings.Contains(lower, "container"):
		return "container-metadata"
	case strings.Contains(lower, "ec2"), strings.Contains(lower, "instance"):
		return "instance-metadata"
	default:
		return "standard-sdk-chain"
	}
}
