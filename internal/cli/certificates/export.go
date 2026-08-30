package certificates

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	modernpkcs12 "software.sslmate.com/src/go-pkcs12"
)

const maxCertificateExportFileSize int64 = 32 << 20

// certificateExportResult is the metadata-only result for certificates export.
// It intentionally contains no certificate, CSR, private-key, or password data.
type certificateExportResult struct {
	Operation         string `json:"operation"`
	CertificatePath   string `json:"certificatePath"`
	PrivateKeyPath    string `json:"privateKeyPath"`
	CSRPath           string `json:"csrPath,omitempty"`
	P12Out            string `json:"p12Out"`
	CertificateSHA256 string `json:"certificateSha256"`
	NotBefore         string `json:"notBefore"`
	NotAfter          string `json:"notAfter"`
	KeyType           string `json:"keyType"`
	KeySize           int    `json:"keySize"`
	PrivateKeyMatched bool   `json:"privateKeyMatched"`
	CSRMatched        *bool  `json:"csrMatched,omitempty"`
}

type certificateExportOptions struct {
	CertificatePath string
	PrivateKeyPath  string
	CSRPath         string
	PasswordPath    string
	P12Out          string
	Force           bool
}

type certificateExportInput struct {
	Data []byte
}

// CertificatesExportCommand returns the local certificate packaging command.
func CertificatesExportCommand() *ffcli.Command {
	fs := flag.NewFlagSet("export", flag.ExitOnError)

	certificatePath := fs.String("certificate", "", "Apple-issued X.509 certificate path (DER .cer or PEM)")
	privateKeyPath := fs.String("private-key", "", "Matching unencrypted RSA or EC private key path (PEM)")
	csrPath := fs.String("csr", "", "Optional CSR path to verify against the certificate and private key")
	passwordPath := fs.String("password-file", "", "Protected file containing the PKCS#12 password")
	p12Out := fs.String("p12-out", "", "Destination path for the password-protected PKCS#12 identity")
	force := fs.Bool("force", false, "Replace an existing PKCS#12 identity")
	confirm := fs.Bool("confirm", false, "Confirm replacement when --force is set")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "export",
		ShortUsage: "asc certificates export --certificate ./push/push.cer --private-key ./push/push.key --password-file ./push/password --p12-out ./push/push.p12 [--csr ./push/push.csr] [--force --confirm]",
		ShortHelp:  "Package a certificate and private key as a protected PKCS#12 identity.",
		LongHelp: "Package an Apple-issued certificate and its matching private key as a\n" +
			"password-protected PKCS#12 identity. This command is local-only: obtain the\n" +
			"certificate through Apple's Developer website after uploading the CSR.\n\n" +
			"The command accepts DER or PEM certificates, validates the private-key match,\n" +
			"and optionally verifies the original CSR. It never prints key material or\n" +
			"writes binary PKCS#12 data to stdout. Replacing an existing output requires\n" +
			"both --force and --confirm.\n\n" +
			"Examples:\n" +
			"  asc certificates export --certificate \"./push/push.cer\" --private-key \"./push/push.key\" --password-file \"./secrets/push.p12.password\" --p12-out \"./push/push.p12\"\n" +
			"  asc certificates export --certificate \"./push/push.cer\" --private-key \"./push/push.key\" --csr \"./push/push.csr\" --password-file \"./secrets/push.p12.password\" --p12-out \"./push/push.p12\" --output json\n" +
			"  asc certificates export --certificate \"./push/push.cer\" --private-key \"./push/push.key\" --password-file \"./secrets/push.p12.password\" --p12-out \"./push/push.p12\" --force --confirm",
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				fmt.Fprintln(os.Stderr, "Error: certificates export does not accept positional arguments")
				return shared.UsageError("certificates export does not accept positional arguments")
			}

			certificateValue := strings.TrimSpace(*certificatePath)
			if certificateValue == "" {
				fmt.Fprintln(os.Stderr, "Error: --certificate is required")
				return shared.MissingRequiredUsageError("--certificate")
			}
			privateKeyValue := strings.TrimSpace(*privateKeyPath)
			if privateKeyValue == "" {
				fmt.Fprintln(os.Stderr, "Error: --private-key is required")
				return shared.MissingRequiredUsageError("--private-key")
			}
			passwordValue := strings.TrimSpace(*passwordPath)
			if passwordValue == "" {
				fmt.Fprintln(os.Stderr, "Error: --password-file is required")
				return shared.MissingRequiredUsageError("--password-file")
			}
			p12Value := strings.TrimSpace(*p12Out)
			if p12Value == "" {
				fmt.Fprintln(os.Stderr, "Error: --p12-out is required")
				return shared.MissingRequiredUsageError("--p12-out")
			}
			if _, err := shared.ValidateOutputFormat(*output.Output, *output.Pretty); err != nil {
				return shared.UsageError(err.Error())
			}
			if *force && !*confirm {
				fmt.Fprintln(os.Stderr, "Error: --confirm is required with --force")
				return shared.MissingRequiredUsageError("--confirm")
			}

			result, err := runCertificateExport(ctx, certificateExportOptions{
				CertificatePath: certificateValue,
				PrivateKeyPath:  privateKeyValue,
				CSRPath:         strings.TrimSpace(*csrPath),
				PasswordPath:    passwordValue,
				P12Out:          p12Value,
				Force:           *force,
			})
			if err != nil {
				return fmt.Errorf("certificates export: %w", err)
			}

			return shared.PrintOutputWithRenderers(
				result,
				*output.Output,
				*output.Pretty,
				func() error { return renderCertificateExportResult(result, false) },
				func() error { return renderCertificateExportResult(result, true) },
			)
		},
	}
}

func runCertificateExport(ctx context.Context, opts certificateExportOptions) (*certificateExportResult, error) {
	_ = ctx

	certificatePath, err := validateCertificateExportInputPath(opts.CertificatePath, "--certificate")
	if err != nil {
		return nil, err
	}
	privateKeyPath, err := validateCertificateExportInputPath(opts.PrivateKeyPath, "--private-key")
	if err != nil {
		return nil, err
	}
	passwordPath, err := validateCertificateExportInputPath(opts.PasswordPath, "--password-file")
	if err != nil {
		return nil, err
	}
	p12Out, err := validateCertificateExportOutputPath(opts.P12Out)
	if err != nil {
		return nil, err
	}
	csrPath := strings.TrimSpace(opts.CSRPath)
	if csrPath != "" {
		csrPath, err = validateCertificateExportInputPath(csrPath, "--csr")
		if err != nil {
			return nil, err
		}
	}

	inputPaths := []string{certificatePath, privateKeyPath, passwordPath}
	if csrPath != "" {
		inputPaths = append(inputPaths, csrPath)
	}
	if err := preflightCertificateExportDestination(p12Out, opts.Force, inputPaths...); err != nil {
		return nil, err
	}

	certificateInput, err := readCertificateExportInput(certificatePath, "certificate", false)
	if err != nil {
		return nil, err
	}
	defer clearCertificateExportBytes(certificateInput.Data)
	certificate, err := parseCertificateExportCertificate(certificateInput.Data)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, fmt.Errorf("certificate is not currently valid")
	}

	privateKeyInput, err := readCertificateExportInput(privateKeyPath, "private key", true)
	if err != nil {
		return nil, err
	}
	defer clearCertificateExportBytes(privateKeyInput.Data)
	privateKey, err := parseCertificateExportPrivateKey(privateKeyInput.Data)
	if err != nil {
		return nil, err
	}
	if !certificateExportPublicKeysEqual(privateKey, certificate.PublicKey) {
		return nil, fmt.Errorf("private key does not match certificate")
	}

	var csrMatched *bool
	if csrPath != "" {
		csrInput, readErr := readCertificateExportInput(csrPath, "CSR", false)
		if readErr != nil {
			return nil, readErr
		}
		defer clearCertificateExportBytes(csrInput.Data)
		csr, parseErr := parseCertificateExportCSR(csrInput.Data)
		if parseErr != nil {
			return nil, parseErr
		}
		matched := certificateExportPublicKeysEqual(csr.PublicKey, certificate.PublicKey) && certificateExportPublicKeysEqual(privateKey, csr.PublicKey)
		if !matched {
			return nil, fmt.Errorf("CSR public key does not match certificate and private key")
		}
		csrMatched = &matched
	}

	passwordInput, err := readCertificateExportInput(passwordPath, "password", true)
	if err != nil {
		return nil, err
	}
	defer clearCertificateExportBytes(passwordInput.Data)
	password := trimCertificateExportPassword(passwordInput.Data)
	if len(password) == 0 {
		return nil, fmt.Errorf("password file contains an empty password")
	}

	p12Data, err := modernpkcs12.Modern2023.WithRand(cryptorand.Reader).Encode(privateKey, certificate, nil, string(password))
	if err != nil {
		return nil, fmt.Errorf("encode PKCS#12 identity: %w", err)
	}
	defer clearCertificateExportBytes(p12Data)

	if _, err := shared.SafeWriteFileNoSymlink(
		p12Out,
		0o600,
		opts.Force,
		".asc-cert-export-*",
		".asc-cert-export-backup-*",
		func(file *os.File) (int64, error) {
			n, writeErr := file.Write(p12Data)
			return int64(n), writeErr
		},
	); err != nil {
		return nil, fmt.Errorf("write --p12-out: %w", err)
	}

	keyType, keySize := certificateExportKeyDetails(privateKey)
	result := &certificateExportResult{
		Operation:         "certificates export",
		CertificatePath:   certificatePath,
		PrivateKeyPath:    privateKeyPath,
		CSRPath:           csrPath,
		P12Out:            p12Out,
		CertificateSHA256: certificateExportCertificateSHA256(certificate),
		NotBefore:         certificate.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          certificate.NotAfter.UTC().Format(time.RFC3339),
		KeyType:           keyType,
		KeySize:           keySize,
		PrivateKeyMatched: true,
		CSRMatched:        csrMatched,
	}
	return result, nil
}

func validateCertificateExportInputPath(path, flagName string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", shared.UsageErrorf("%s is required", flagName)
	}
	if isCertificateExportDirectoryPath(trimmed) {
		return "", shared.UsageErrorf("%s must be a file path", flagName)
	}
	return trimmed, nil
}

func validateCertificateExportOutputPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", shared.UsageError("--p12-out is required")
	}
	if trimmed == "-" {
		return "", shared.UsageError("--p12-out must be a file path, not stdout")
	}
	if isCertificateExportDirectoryPath(trimmed) {
		return "", shared.UsageError("--p12-out must be a file path")
	}
	return trimmed, nil
}

func isCertificateExportDirectoryPath(path string) bool {
	if path == "" {
		return false
	}
	last := path[len(path)-1]
	return os.IsPathSeparator(last) || last == '\\'
}

func preflightCertificateExportDestination(output string, force bool, inputs ...string) error {
	outputAbs, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve --p12-out: %w", err)
	}
	outputAbs = filepath.Clean(outputAbs)
	for _, input := range inputs {
		inputAbs, absErr := filepath.Abs(input)
		if absErr != nil {
			return fmt.Errorf("resolve input path: %w", absErr)
		}
		if outputAbs == filepath.Clean(inputAbs) {
			return fmt.Errorf("--p12-out must differ from input path %q", input)
		}
	}

	info, err := os.Lstat(output)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect --p12-out: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink %q", output)
	}
	if info.IsDir() {
		return fmt.Errorf("--p12-out %q is a directory", output)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("--p12-out %q is not a regular file", output)
	}
	if !force {
		return fmt.Errorf("output file already exists: %w", os.ErrExist)
	}

	for _, input := range inputs {
		inputInfo, statErr := os.Stat(input)
		if statErr != nil {
			continue
		}
		if os.SameFile(info, inputInfo) {
			return fmt.Errorf("--p12-out must not resolve to input path %q", input)
		}
	}
	return nil
}

func readCertificateExportInput(path, label string, protected bool) (certificateExportInput, error) {
	file, err := shared.OpenExistingNoFollow(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return certificateExportInput{}, fmt.Errorf("%s file does not exist", label)
		}
		return certificateExportInput{}, fmt.Errorf("open %s without following symlinks: %w", label, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return certificateExportInput{}, fmt.Errorf("inspect %s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return certificateExportInput{}, fmt.Errorf("%s must be a regular file", label)
	}
	if protected && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return certificateExportInput{}, fmt.Errorf("%s permissions must be 0600 or more restrictive", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCertificateExportFileSize+1))
	if err != nil {
		return certificateExportInput{}, fmt.Errorf("read %s: %w", label, err)
	}
	if len(data) == 0 {
		return certificateExportInput{}, fmt.Errorf("%s is empty", label)
	}
	if int64(len(data)) > maxCertificateExportFileSize {
		return certificateExportInput{}, fmt.Errorf("%s exceeds the 32 MiB size limit", label)
	}
	return certificateExportInput{Data: data}, nil
}

func parseCertificateExportCertificate(data []byte) (*x509.Certificate, error) {
	der, err := parseCertificateExportObject(data, "certificate", map[string]bool{"CERTIFICATE": true})
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certificate is not a valid X.509 certificate: %w", err)
	}
	return certificate, nil
}

func parseCertificateExportCSR(data []byte) (*x509.CertificateRequest, error) {
	der, err := parseCertificateExportObject(data, "CSR", map[string]bool{
		"CERTIFICATE REQUEST":     true,
		"NEW CERTIFICATE REQUEST": true,
	})
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("CSR is not a valid PKCS#10 request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature is invalid: %w", err)
	}
	return csr, nil
}

func parseCertificateExportObject(data []byte, label string, pemTypes map[string]bool) ([]byte, error) {
	if block, rest := pem.Decode(data); block != nil {
		if !pemTypes[block.Type] {
			return nil, fmt.Errorf("%s PEM block type %q is unsupported", label, block.Type)
		}
		if next, trailing := pem.Decode(rest); next != nil || len(bytes.TrimSpace(trailing)) != 0 {
			return nil, fmt.Errorf("%s must contain exactly one object", label)
		}
		return parseCertificateExportDER(block.Bytes, label)
	}
	return parseCertificateExportDER(data, label)
}

func parseCertificateExportDER(data []byte, label string) ([]byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil || len(rest) != 0 || len(raw.FullBytes) == 0 {
		return nil, fmt.Errorf("%s must contain exactly one DER object", label)
	}
	return raw.FullBytes, nil
}

func parseCertificateExportPrivateKey(data []byte) (any, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("private key must contain exactly one PEM object")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if err := validateCertificateExportPrivateKeyType(key); err != nil {
			return nil, err
		}
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("private key must be an unencrypted RSA or EC private key")
}

func validateCertificateExportPrivateKeyType(key any) error {
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return nil
	default:
		return fmt.Errorf("private key must be an RSA or EC private key")
	}
}

func certificateExportPublicKeysEqual(privateOrPublic, public any) bool {
	var derived any
	if signer, ok := privateOrPublic.(crypto.Signer); ok {
		derived = signer.Public()
	} else {
		derived = privateOrPublic
	}
	derivedDER, err := x509.MarshalPKIXPublicKey(derived)
	if err != nil {
		return false
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return false
	}
	return bytes.Equal(derivedDER, publicDER)
}

func certificateExportCertificateSHA256(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}
	sum := sha256.Sum256(certificate.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func certificateExportKeyDetails(key any) (string, int) {
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		return "RSA", typed.N.BitLen()
	case *ecdsa.PrivateKey:
		if typed.Curve != nil && typed.Params() != nil {
			return "EC", typed.Params().BitSize
		}
		return "EC", 0
	default:
		return "", 0
	}
}

func trimCertificateExportPassword(data []byte) []byte {
	if bytes.HasSuffix(data, []byte("\r\n")) {
		return data[:len(data)-2]
	}
	if bytes.HasSuffix(data, []byte("\n")) {
		return data[:len(data)-1]
	}
	return data
}

func clearCertificateExportBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func renderCertificateExportResult(result *certificateExportResult, markdown bool) error {
	if result == nil {
		return fmt.Errorf("result is nil")
	}
	render := asc.RenderTable
	if markdown {
		render = asc.RenderMarkdown
	}
	rows := [][]string{
		{"operation", result.Operation},
		{"certificate_path", result.CertificatePath},
		{"private_key_path", result.PrivateKeyPath},
		{"p12_out", result.P12Out},
		{"certificate_sha256", result.CertificateSHA256},
		{"not_before", result.NotBefore},
		{"not_after", result.NotAfter},
		{"key_type", result.KeyType},
		{"key_size", fmt.Sprintf("%d", result.KeySize)},
		{"private_key_matched", fmt.Sprintf("%t", result.PrivateKeyMatched)},
	}
	if result.CSRPath != "" {
		rows = append(
			rows,
			[]string{"csr_path", result.CSRPath},
			[]string{"csr_matched", fmt.Sprintf("%t", result.CSRMatched != nil && *result.CSRMatched)},
		)
	}
	render([]string{"field", "value"}, rows)
	return nil
}
