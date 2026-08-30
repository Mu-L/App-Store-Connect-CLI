package signing

import (
	"errors"
	"reflect"
)

// ErrSigningResignCleanupFailed marks a cleanup failure that may leave the
// temporary signing environment for recovery. Its concrete cause remains
// available through errors.Is/errors.As, while the public wrapper renders only
// the stable cleanup stage/code.
var ErrSigningResignCleanupFailed = errors.New("signing resign cleanup failed")

// signingResignOperationalStage identifies the public phase of a re-signing
// operation.  It is deliberately closed: values from paths, tool output, and
// operating-system errors must never become part of a public diagnostic.
type signingResignOperationalStage uint8

const (
	signingResignStagePreparation signingResignOperationalStage = iota + 1
	signingResignStageSigning
	signingResignStageVerification
	signingResignStageCertificate
	signingResignStageArtifact
	signingResignStageEnvironment
	signingResignStageCleanup
)

func (stage signingResignOperationalStage) String() string {
	switch stage {
	case signingResignStagePreparation:
		return "preparation"
	case signingResignStageSigning:
		return "signing"
	case signingResignStageVerification:
		return "verification"
	case signingResignStageCertificate:
		return "certificate inspection"
	case signingResignStageArtifact:
		return "artifact verification"
	case signingResignStageEnvironment:
		return "signing environment"
	case signingResignStageCleanup:
		return "cleanup"
	default:
		return "operation"
	}
}

// signingResignOperationalCode identifies the stable, non-sensitive reason a
// re-signing operation could not complete.  Keep this list closed so public
// errors cannot accidentally include a path or provider/tool diagnostic.
type signingResignOperationalCode uint8

const (
	signingResignCodeFilesystem signingResignOperationalCode = iota + 1
	signingResignCodeGeneratedEntitlements
	signingResignCodeCertificate
	signingResignCodeArtifactRead
	signingResignCodeArtifactHash
	signingResignCodeArtifactPublish
	signingResignCodeSigning
	signingResignCodeVerification
	signingResignCodeEnvironment
	signingResignCodeCleanup
)

func (code signingResignOperationalCode) String() string {
	switch code {
	case signingResignCodeFilesystem:
		return "filesystem"
	case signingResignCodeGeneratedEntitlements:
		return "generated-entitlements"
	case signingResignCodeCertificate:
		return "certificate"
	case signingResignCodeArtifactRead:
		return "artifact-read"
	case signingResignCodeArtifactHash:
		return "artifact-hash"
	case signingResignCodeArtifactPublish:
		return "artifact-publish"
	case signingResignCodeSigning:
		return "signing"
	case signingResignCodeVerification:
		return "verification"
	case signingResignCodeEnvironment:
		return "environment"
	case signingResignCodeCleanup:
		return "cleanup"
	default:
		return "operation"
	}
}

// signingResignOperationalError keeps detailed causes available to internal
// callers through errors.Is/errors.As while exposing only the closed phase and
// code through Error(). This is the boundary used by the public resign CLI;
// paths, keychain names, profile selectors, and tool diagnostics stay private.
type signingResignOperationalError struct {
	stage signingResignOperationalStage
	code  signingResignOperationalCode
	err   error
}

func (err *signingResignOperationalError) Error() string {
	if err == nil {
		return "signing resign operation failed"
	}
	return "signing resign failed during " + err.stage.String() + " (" + err.code.String() + ")"
}

func (err *signingResignOperationalError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.err
}

func wrapSigningResignOperationalError(stage signingResignOperationalStage, code signingResignOperationalCode, err error) error {
	if err == nil {
		return nil
	}
	if signingResignOperationalErrorTree(err) {
		return err
	}
	return &signingResignOperationalError{stage: stage, code: code, err: err}
}

// signingResignOperationalErrorTree reports whether every error in an
// aggregate is already public-safe. This lets a callback's signing,
// verification, artifact, and cleanup stages retain their distinct codes even
// when cleanup adds a second typed error, while a mixed aggregate is still
// hidden behind one stable outer error.
func signingResignOperationalErrorTree(err error) bool {
	if err == nil {
		return true
	}
	var alreadyWrapped *signingResignOperationalError
	if errors.As(err, &alreadyWrapped) && isDirectSigningResignOperationalError(err, alreadyWrapped) {
		return true
	}
	if multiple, ok := err.(interface{ Unwrap() []error }); ok {
		causes := multiple.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !signingResignOperationalErrorTree(cause) {
				return false
			}
		}
		return true
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		return signingResignOperationalErrorTree(single.Unwrap())
	}
	return false
}

func isDirectSigningResignOperationalError(err error, candidate *signingResignOperationalError) bool {
	if candidate == nil {
		return false
	}
	errType := reflect.TypeOf(err)
	candidateType := reflect.TypeOf(candidate)
	if errType != candidateType || errType.Kind() != reflect.Pointer {
		return false
	}
	return reflect.ValueOf(err).Pointer() == reflect.ValueOf(candidate).Pointer()
}
