package signing

import (
	"errors"
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

// publicSafeSigningResignError marks the typed operational error itself as
// public-safe. The marker exists so the tree check below can require the
// outermost error to be the typed value without errors.As, which would also
// accept plain wrappers whose prefix text must never reach public output.
func (err *signingResignOperationalError) publicSafeSigningResignError() {}

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
// aggregate is already public-safe. Only a typed operational error itself, or
// an aggregate whose members are all public-safe, qualifies: a plain wrapper
// around a typed cause would surface its own prefix text through Error(), so
// it must be re-wrapped before it can reach public output. This still lets a
// callback's signing, verification, artifact, and cleanup stages retain their
// distinct codes when cleanup joins a second typed error.
func signingResignOperationalErrorTree(err error) bool {
	if err == nil {
		return true
	}
	if _, ok := err.(interface{ publicSafeSigningResignError() }); ok {
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
	return false
}
