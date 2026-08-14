package distribution

import "errors"

var (
	// ErrPrivatePublishLinkExpired means an immutable private install lease can
	// no longer be verified and must be replaced by a newly authorized run.
	ErrPrivatePublishLinkExpired = errors.New("private publication link expired")
	// ErrPrivatePublishProfileExpired means the signed payload is no longer
	// usable for publication and must be rebuilt under a new plan.
	ErrPrivatePublishProfileExpired = errors.New("private publication profile expired")
	// ErrPrivatePublishConflict means exact immutable local or remote evidence
	// conflicts with the saved publication intent. Retrying cannot repair it.
	ErrPrivatePublishConflict = errors.New("private publication intent conflict")
	// ErrImmutableObjectConflict means an existing object at an exact key does
	// not match the expected immutable content identity.
	ErrImmutableObjectConflict = errors.New("immutable object conflict")
	// ErrVerificationContentConflict retains the orchestration classification
	// while sharing the landed verifier's deterministic mismatch sentinel.
	ErrVerificationContentConflict = ErrObjectVerificationMismatch
)
