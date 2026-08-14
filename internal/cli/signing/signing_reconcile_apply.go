package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

func executeSigningReconcileApply(ctx context.Context, planPath string) (signingReconcileReceipt, error) {
	plan, err := readSigningPlanArtifact(filepath.Clean(strings.TrimSpace(planPath)))
	if err != nil {
		return signingReconcileReceipt{}, err
	}
	if !plan.Ready || len(plan.Blockers) > 0 {
		return signingReconcileReceipt{}, shared.UsageError("signing reconcile plan is blocked; rerun plan after resolving blockers")
	}
	if err := validateSigningApplyPlan(plan); err != nil {
		return signingReconcileReceipt{}, shared.UsageErrorf("invalid signing reconcile plan: %v", err)
	}
	if plan.MutationCount > plan.MaxMutations {
		return signingReconcileReceipt{}, shared.UsageError("signing reconcile plan exceeds its mutation ceiling")
	}
	if err := verifySigningLocalInputs(plan); err != nil {
		return signingReconcileReceipt{}, shared.UsageErrorf("local inputs changed: %v; rerun asc signing reconcile plan", err)
	}

	receipt, err := loadOrStartSigningReceipt(plan)
	if err != nil {
		return signingReconcileReceipt{}, err
	}
	client, err := shared.GetASCClient()
	if err != nil {
		return receipt, err
	}
	requestCtx, cancel := shared.ContextWithTimeout(ctx)
	defer cancel()
	certificates, err := getAllReconcileCertificates(requestCtx, client)
	if err != nil {
		return receipt, fmt.Errorf("reread certificates: %w", err)
	}
	selectedCertificate, certificateBlockers := selectReconcileCertificate(certificates, plan.Certificate.ID, time.Now(), plan.MinimumValidityDays)
	if len(certificateBlockers) > 0 || selectedCertificate == nil || !reflect.DeepEqual(*selectedCertificate, *plan.Certificate) {
		return receipt, shared.UsageError("selected certificate changed or is no longer eligible; rerun asc signing reconcile plan")
	}

	deviceData, err := readProtectedFile(plan.Paths.DevicesFile)
	if err != nil {
		return receipt, err
	}
	devicesFile, err := decodeSigningDevicesFile(deviceData)
	if err != nil {
		return receipt, shared.UsageErrorf("invalid devices file: %v", err)
	}
	if err := preflightSigningApply(requestCtx, client, plan, devicesFile); err != nil {
		return receipt, shared.UsageErrorf("remote signing state changed: %v; rerun asc signing reconcile plan", err)
	}
	createdProfiles := make(map[string]string)

	for _, action := range plan.Actions {
		item := signingActionReceipt{ID: action.ID, Kind: action.Kind, Status: "running"}
		receipt.Actions = append(receipt.Actions, item)
		index := len(receipt.Actions) - 1
		if err := persistSigningReceipt(&receipt); err != nil {
			return receipt, err
		}

		resourceID, outputPath, actionErr := applySigningAction(requestCtx, client, plan, devicesFile, action, createdProfiles)
		receipt.Actions[index].ResourceID = resourceID
		receipt.Actions[index].OutputPath = outputPath
		if actionErr != nil {
			actionErr = sanitizeReconcileError(actionErr, devicesFile)
			receipt.Actions[index].Status = "failed"
			receipt.Actions[index].Error = actionErr.Error()
			_ = persistSigningReceipt(&receipt)
			return receipt, fmt.Errorf("action %s: %w", action.ID, actionErr)
		}
		receipt.Actions[index].Status = "completed"
		if action.Kind == actionCreateProfile {
			createdProfiles[action.BundleID] = resourceID
		}
		if err := persistSigningReceipt(&receipt); err != nil {
			return receipt, err
		}
	}
	receipt.Complete = true
	if err := persistSigningReceipt(&receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func preflightSigningApply(ctx context.Context, client *asc.Client, plan signingReconcilePlanArtifact, devicesFile signingDevicesFile) error {
	remoteDevices, err := getAllReconcileDevices(ctx, client)
	if err != nil {
		return fmt.Errorf("list devices: %w", err)
	}
	resolved, deviceActions, blockers := planDesiredDevices(devicesFile.Devices, remoteDevices)
	if len(blockers) > 0 {
		return fmt.Errorf("device preconditions blocked: %s", strings.Join(blockers, "; "))
	}
	plannedMutations := make(map[string]string)
	for _, action := range plan.Actions {
		switch action.Kind {
		case actionRegisterDevice, actionCreateBundleID, actionCreateProfile:
			plannedMutations[action.ID] = action.Kind
		}
	}
	for _, action := range deviceActions {
		if plannedMutations[action.ID] != action.Kind {
			return fmt.Errorf("devices now require unplanned %s", action.Kind)
		}
	}
	for _, target := range plan.Targets {
		_, actions, targetBlockers, err := planSigningTarget(ctx, client, target, resolved, plan.Certificate, plan.MinimumValidityDays)
		if err != nil {
			return fmt.Errorf("bundle %s: %w", target.BundleID, err)
		}
		if len(targetBlockers) > 0 {
			return fmt.Errorf("bundle %s blocked: %s", target.BundleID, strings.Join(targetBlockers, "; "))
		}
		for _, action := range actions {
			switch action.Kind {
			case actionRegisterDevice, actionCreateBundleID, actionCreateProfile:
				if plannedMutations[action.ID] != action.Kind {
					return fmt.Errorf("bundle %s now requires unplanned %s", target.BundleID, action.Kind)
				}
			}
		}
	}
	for _, action := range plan.Actions {
		if action.Kind != actionDownloadProfile {
			continue
		}
		target, ok := targetByBundleID(plan.Targets, action.BundleID)
		if !ok {
			return fmt.Errorf("download target %s is missing", action.BundleID)
		}
		if _, _, err := verifyReconcileProfile(ctx, client, action.ProfileID, plan, devicesFile, target); err != nil {
			return fmt.Errorf("planned profile %s changed: %w", action.ProfileID, err)
		}
	}
	return nil
}

func validateSigningApplyPlan(plan signingReconcilePlanArtifact) error {
	if plan.Certificate == nil || strings.TrimSpace(plan.Certificate.ID) == "" {
		return fmt.Errorf("selected certificate is missing")
	}
	digest, err := hex.DecodeString(strings.TrimSpace(plan.Certificate.SHA256))
	if err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("selected certificate SHA-256 is invalid")
	}
	if plan.MaxMutations < 1 || plan.MutationCount < 0 {
		return fmt.Errorf("mutation limits are invalid")
	}
	if plan.MinimumValidityDays < 0 || plan.MinimumValidityDays > reconcileMaximumValidityDays {
		return fmt.Errorf("minimum validity days are invalid")
	}
	mutations := 0
	seenActions := make(map[string]struct{}, len(plan.Actions))
	for _, action := range plan.Actions {
		if strings.TrimSpace(action.ID) == "" {
			return fmt.Errorf("action ID is missing")
		}
		if _, exists := seenActions[action.ID]; exists {
			return fmt.Errorf("duplicate action ID %q", action.ID)
		}
		seenActions[action.ID] = struct{}{}
		switch action.Kind {
		case actionRegisterDevice:
			if action.ID != "device:"+action.DeviceFingerprint || !planContainsDevice(plan, action.DeviceFingerprint) {
				return fmt.Errorf("register-device action differs from desired devices")
			}
			mutations++
		case actionCreateBundleID:
			if action.ID != "bundle:"+action.BundleID || !planContainsTarget(plan, action.BundleID) {
				return fmt.Errorf("create-bundle action differs from targets")
			}
			mutations++
		case actionCreateProfile:
			if action.ID != "profile:"+action.BundleID || !planContainsTarget(plan, action.BundleID) || action.CertificateID != plan.Certificate.ID {
				return fmt.Errorf("create-profile action differs from targets or certificate")
			}
			mutations++
		case actionDownloadProfile:
			if action.ID != "download:"+action.BundleID || !planContainsTarget(plan, action.BundleID) || strings.TrimSpace(action.ProfileID) == "" {
				return fmt.Errorf("download-profile action differs from targets")
			}
		default:
			return fmt.Errorf("unsupported action kind %q", action.Kind)
		}
	}
	if mutations != plan.MutationCount {
		return fmt.Errorf("mutation count differs from actions")
	}
	return nil
}

func planContainsTarget(plan signingReconcilePlanArtifact, bundleID string) bool {
	_, ok := targetByBundleID(plan.Targets, bundleID)
	return ok
}

func planContainsDevice(plan signingReconcilePlanArtifact, fingerprint string) bool {
	for _, device := range plan.Devices {
		if device.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

func verifySigningLocalInputs(plan signingReconcilePlanArtifact) error {
	archive, err := readSigningArchiveRequirements(plan.Paths.ArchivePath)
	if err != nil {
		return fmt.Errorf("inspect archive: %w", err)
	}
	if archive.TeamID != plan.TeamID || !reflect.DeepEqual(archive.Targets, plan.Targets) {
		return fmt.Errorf("archive signing requirements differ from plan")
	}
	data, err := readProtectedFile(plan.Paths.DevicesFile)
	if err != nil {
		return fmt.Errorf("read devices file: %w", err)
	}
	devices, err := decodeSigningDevicesFile(data)
	if err != nil {
		return err
	}
	if len(devices.Devices) != len(plan.Devices) {
		return fmt.Errorf("desired device count differs from plan")
	}
	for index, device := range devices.Devices {
		planned := plan.Devices[index]
		if fingerprintReconcileName(device.Name) != planned.NameSHA256 || device.Platform != planned.Platform || device.Fingerprint != planned.Fingerprint {
			return fmt.Errorf("desired device %s differs from plan", device.Fingerprint)
		}
	}
	return nil
}

func loadOrStartSigningReceipt(plan signingReconcilePlanArtifact) (signingReconcileReceipt, error) {
	receiptPath := filepath.Join(plan.Paths.StateDir, "receipt.json")
	data, err := readProtectedFile(receiptPath)
	if err == nil {
		var receipt signingReconcileReceipt
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&receipt); err != nil {
			return receipt, fmt.Errorf("decode receipt: %w", err)
		}
		if err := ensureJSONEOF(decoder); err != nil {
			return receipt, fmt.Errorf("decode receipt: %w", err)
		}
		if receipt.SchemaVersion != signingReconcileSchemaV1 || receipt.PlanHash != plan.PlanHash {
			return receipt, shared.UsageError("existing receipt belongs to a different plan; move it aside before apply")
		}
		// Receipt state is a recovery hint, never proof of a durable outcome. A
		// resumed apply reruns every idempotent ensure/verification action so
		// remote drift and missing/corrupt local profiles are repaired or blocked.
		receipt.Actions = nil
		receipt.Complete = false
		return receipt, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return signingReconcileReceipt{}, err
	}
	now := nowRFC3339()
	return signingReconcileReceipt{
		SchemaVersion: signingReconcileSchemaV1, PlanHash: plan.PlanHash,
		StartedAt: now, UpdatedAt: now, StateDir: plan.Paths.StateDir,
		ReceiptPath: receiptPath,
	}, nil
}

func persistSigningReceipt(receipt *signingReconcileReceipt) error {
	receipt.UpdatedAt = nowRFC3339()
	return writeSigningStateJSON(receipt.StateDir, "receipt.json", *receipt, true)
}

func sanitizeReconcileError(err error, devices signingDevicesFile) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	for _, device := range devices.Devices {
		secrets := []string{
			device.UDID,
			normalizeReconcileUDID(device.UDID),
			url.QueryEscape(device.UDID),
			url.PathEscape(device.UDID),
			device.Name,
			url.QueryEscape(device.Name),
		}
		for _, secret := range uniqueSortedStrings(secrets) {
			if secret != "" {
				message = strings.ReplaceAll(message, secret, "[redacted]")
			}
		}
	}
	return errors.New(message)
}

func applySigningAction(ctx context.Context, client *asc.Client, plan signingReconcilePlanArtifact, devicesFile signingDevicesFile, action signingAction, createdProfiles map[string]string) (string, string, error) {
	switch action.Kind {
	case actionRegisterDevice:
		input, ok := desiredDeviceInput(devicesFile, action.DeviceFingerprint)
		if !ok {
			return "", "", fmt.Errorf("device input is missing")
		}
		resource, err := ensureReconcileDevice(ctx, client, input)
		if err != nil {
			return "", "", err
		}
		return resource.ID, "", nil
	case actionCreateBundleID:
		bundle, err := ensureReconcileBundleID(ctx, client, action.BundleID)
		if err != nil {
			return "", "", err
		}
		return bundle.ID, "", nil
	case actionCreateProfile:
		target, ok := targetByBundleID(plan.Targets, action.BundleID)
		if !ok {
			return "", "", fmt.Errorf("target is missing from plan")
		}
		profile, content, err := ensureReconcileProfile(ctx, client, plan, devicesFile, action, target)
		if err != nil {
			return "", "", err
		}
		output, err := writeVerifiedProfile(plan.Paths.StateDir, content)
		if err != nil {
			return profile.ID, "", err
		}
		return profile.ID, output, nil
	case actionDownloadProfile:
		profileID := action.ProfileID
		if created := createdProfiles[action.BundleID]; created != "" {
			profileID = created
		}
		target, ok := targetByBundleID(plan.Targets, action.BundleID)
		if !ok {
			return "", "", fmt.Errorf("target is missing from plan")
		}
		profile, content, err := verifyReconcileProfile(ctx, client, profileID, plan, devicesFile, target)
		if err != nil {
			return "", "", err
		}
		output, err := writeVerifiedProfile(plan.Paths.StateDir, content)
		if err != nil {
			return profile.ID, "", err
		}
		return profile.ID, output, nil
	default:
		return "", "", fmt.Errorf("unsupported planned action kind %q", action.Kind)
	}
}

func desiredDeviceInput(devices signingDevicesFile, fingerprint string) (signingDeviceInput, bool) {
	for _, device := range devices.Devices {
		if device.Fingerprint == fingerprint {
			return device, true
		}
	}
	return signingDeviceInput{}, false
}

func ensureReconcileDevice(ctx context.Context, client *asc.Client, input signingDeviceInput) (*asc.Resource[asc.DeviceAttributes], error) {
	find := func() (*asc.Resource[asc.DeviceAttributes], error) {
		devices, err := getAllReconcileDevices(ctx, client)
		if err != nil {
			return nil, err
		}
		var enabled, disabled []asc.Resource[asc.DeviceAttributes]
		for _, device := range devices {
			if normalizeReconcileUDID(device.Attributes.UDID) != normalizeReconcileUDID(input.UDID) {
				continue
			}
			if device.Attributes.Status == asc.DeviceStatusEnabled {
				enabled = append(enabled, device)
			} else {
				disabled = append(disabled, device)
			}
		}
		if len(enabled) == 1 {
			return &enabled[0], nil
		}
		if len(enabled) > 1 {
			return nil, fmt.Errorf("device %s resolves to multiple enabled resources", input.Fingerprint)
		}
		if len(disabled) > 0 {
			return nil, fmt.Errorf("device %s is disabled; refusing PATCH", input.Fingerprint)
		}
		return nil, nil
	}
	if existing, err := find(); err != nil || existing != nil {
		return existing, err
	}
	created, err := client.CreateDevice(ctx, asc.DeviceCreateAttributes{Name: input.Name, UDID: input.UDID, Platform: asc.DevicePlatformIOS})
	if err == nil {
		return &created.Data, nil
	}
	// Resolve conflict/uncertain completion by exact reread, never blind retry.
	if existing, readErr := find(); readErr == nil && existing != nil {
		return existing, nil
	}
	return nil, err
}

func ensureReconcileBundleID(ctx context.Context, client *asc.Client, identifier string) (*asc.Resource[asc.BundleIDAttributes], error) {
	if existing, err := findExactReconcileBundleID(ctx, client, identifier); err != nil || existing != nil {
		return existing, err
	}
	created, err := client.CreateBundleID(ctx, asc.BundleIDCreateAttributes{Name: "ASC " + identifier, Identifier: identifier, Platform: asc.BundleIDPlatformIOS})
	if err == nil {
		return &created.Data, nil
	}
	if existing, readErr := findExactReconcileBundleID(ctx, client, identifier); readErr == nil && existing != nil {
		return existing, nil
	}
	return nil, err
}

func ensureReconcileProfile(ctx context.Context, client *asc.Client, plan signingReconcilePlanArtifact, devicesFile signingDevicesFile, action signingAction, target signingTarget) (*asc.Resource[asc.ProfileAttributes], []byte, error) {
	bundle, err := findExactReconcileBundleID(ctx, client, action.BundleID)
	if err != nil || bundle == nil {
		if err == nil {
			err = fmt.Errorf("bundle ID is missing after planned actions")
		}
		return nil, nil, err
	}
	if bundle.Attributes.Platform != asc.BundleIDPlatformIOS && bundle.Attributes.Platform != asc.BundleIDPlatformUniversal {
		return nil, nil, fmt.Errorf("bundle ID has incompatible platform %s", bundle.Attributes.Platform)
	}
	if err := verifyReconcileBundleCapabilities(ctx, client, bundle.ID, target.Entitlements); err != nil {
		return nil, nil, err
	}
	resolvedDesired, deviceIDs, err := resolveApplyDesiredDevices(ctx, client, devicesFile)
	if err != nil {
		return nil, nil, err
	}
	// Accept monotonic drift when an exact suitable profile already exists.
	candidates, err := getProfileCandidates(ctx, client, *bundle, target, resolvedDesired, *plan.Certificate, plan.MinimumValidityDays)
	if err != nil {
		return nil, nil, err
	}
	for _, candidate := range candidates {
		if candidate.Suitable {
			return fetchVerifiedProfileContent(ctx, client, candidate.Profile.ID, plan, devicesFile, target)
		}
	}
	created, err := client.CreateProfile(ctx, asc.ProfileCreateAttributes{Name: action.ProfileName, ProfileType: reconcileProfileType}, bundle.ID, []string{plan.Certificate.ID}, deviceIDs)
	if err != nil {
		// A 409 or uncertain response is accepted only if a reread proves the
		// deterministic profile name and exact suitability.
		profiles, readErr := getAllBundleProfiles(ctx, client, bundle.ID)
		if readErr == nil {
			for _, profile := range profiles {
				if profile.Attributes.Name == action.ProfileName {
					if verified, content, verifyErr := fetchVerifiedProfileContent(ctx, client, profile.ID, plan, devicesFile, target); verifyErr == nil {
						return verified, content, nil
					}
				}
			}
		}
		return nil, nil, err
	}
	return fetchVerifiedProfileContent(ctx, client, created.Data.ID, plan, devicesFile, target)
}

func verifyReconcileBundleCapabilities(ctx context.Context, client *asc.Client, bundleResourceID string, entitlements map[string]any) error {
	required, unverified := signingCapabilitiesForEntitlements(entitlements)
	if len(unverified) > 0 {
		return fmt.Errorf("cannot verify entitlement capabilities safely: %s", strings.Join(unverified, ","))
	}
	if len(required) == 0 {
		return nil
	}
	capabilities, err := getAllBundleIDCapabilities(ctx, client, bundleResourceID)
	if err != nil {
		return err
	}
	var enabled []string
	for _, capability := range capabilities {
		enabled = append(enabled, strings.ToUpper(strings.TrimSpace(capability.Attributes.CapabilityType)))
	}
	for _, capability := range required {
		if !containsAllStrings(enabled, []string{capability}) {
			return fmt.Errorf("bundle ID is missing required capability %s; refusing capability mutation", capability)
		}
	}
	return nil
}

func verifyReconcileProfile(ctx context.Context, client *asc.Client, profileID string, plan signingReconcilePlanArtifact, devicesFile signingDevicesFile, target signingTarget) (*asc.Resource[asc.ProfileAttributes], []byte, error) {
	if strings.TrimSpace(profileID) == "" {
		return nil, nil, fmt.Errorf("planned profile ID is empty")
	}
	return fetchVerifiedProfileContent(ctx, client, profileID, plan, devicesFile, target)
}

func fetchVerifiedProfileContent(ctx context.Context, client *asc.Client, profileID string, plan signingReconcilePlanArtifact, devicesFile signingDevicesFile, target signingTarget) (*asc.Resource[asc.ProfileAttributes], []byte, error) {
	profile, err := client.GetProfile(ctx, profileID)
	if err != nil {
		return nil, nil, err
	}
	if profile.Data.Attributes.ProfileType != reconcileProfileType || profile.Data.Attributes.ProfileState != asc.ProfileStateActive {
		return nil, nil, fmt.Errorf("profile is not active IOS_APP_ADHOC")
	}
	expires, err := time.Parse(time.RFC3339, profile.Data.Attributes.ExpirationDate)
	if err != nil || !expires.After(time.Now().Add(time.Duration(plan.MinimumValidityDays)*24*time.Hour)) {
		return nil, nil, fmt.Errorf("profile does not satisfy minimum validity")
	}
	certs, err := getAllProfileCertificateIDs(ctx, client, profileID)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) != 1 || certs[0] != plan.Certificate.ID {
		return nil, nil, fmt.Errorf("profile certificate set differs from plan")
	}
	profileDevices, err := getAllProfileDeviceIDs(ctx, client, profileID)
	if err != nil {
		return nil, nil, err
	}
	desiredIDs, err := resolveApplyDeviceIDs(ctx, client, devicesFile)
	if err != nil {
		return nil, nil, err
	}
	if !sameStringSet(profileDevices, desiredIDs) {
		return nil, nil, fmt.Errorf("profile device set differs from plan")
	}
	encodedContent := strings.TrimSpace(profile.Data.Attributes.ProfileContent)
	if len(encodedContent) > base64.StdEncoding.EncodedLen(reconcileProfileMaxBytes) {
		return nil, nil, fmt.Errorf("profile content exceeds %d bytes", reconcileProfileMaxBytes)
	}
	content, err := base64.StdEncoding.DecodeString(encodedContent)
	if err != nil {
		return nil, nil, fmt.Errorf("decode profile content: %w", err)
	}
	if len(content) > reconcileProfileMaxBytes {
		return nil, nil, fmt.Errorf("profile content exceeds %d bytes", reconcileProfileMaxBytes)
	}
	parsed, err := decodeReconcileMobileProvision(content)
	if err != nil {
		return nil, nil, fmt.Errorf("verify profile content: %w", err)
	}
	if !safeProfileUUID(parsed.UUID) {
		return nil, nil, fmt.Errorf("profile content has unsafe or missing UUID")
	}
	if !parsed.ExpirationDate.After(time.Now().Add(time.Duration(plan.MinimumValidityDays) * 24 * time.Hour)) {
		return nil, nil, fmt.Errorf("profile content does not satisfy minimum validity")
	}
	if !entitlementsContain(parsed.Entitlements, target.Entitlements) {
		return nil, nil, fmt.Errorf("profile entitlements do not contain target entitlements")
	}
	if !mobileProvisionContainsCertificate(parsed, plan.Certificate.SHA256) {
		return nil, nil, fmt.Errorf("profile content does not contain the selected certificate")
	}
	provisioned := make(map[string]struct{})
	for _, udid := range parsed.ProvisionedDevices {
		provisioned[normalizeReconcileUDID(udid)] = struct{}{}
	}
	for _, input := range devicesFile.Devices {
		if _, ok := provisioned[normalizeReconcileUDID(input.UDID)]; !ok {
			return nil, nil, fmt.Errorf("profile content is missing desired device %s", input.Fingerprint)
		}
	}
	if len(provisioned) != len(devicesFile.Devices) {
		return nil, nil, fmt.Errorf("profile content device set differs from plan")
	}
	profile.Data.Attributes.UUID = parsed.UUID
	return &profile.Data, content, nil
}

func resolveApplyDeviceIDs(ctx context.Context, client *asc.Client, devicesFile signingDevicesFile) ([]string, error) {
	_, ids, err := resolveApplyDesiredDevices(ctx, client, devicesFile)
	return ids, err
}

func resolveApplyDesiredDevices(ctx context.Context, client *asc.Client, devicesFile signingDevicesFile) ([]signingDesiredDevice, []string, error) {
	remote, err := getAllReconcileDevices(ctx, client)
	if err != nil {
		return nil, nil, err
	}
	var ids []string
	var desiredResult []signingDesiredDevice
	for _, desired := range devicesFile.Devices {
		var matches []string
		for _, device := range remote {
			if device.Attributes.Status == asc.DeviceStatusEnabled && normalizeReconcileUDID(device.Attributes.UDID) == normalizeReconcileUDID(desired.UDID) {
				matches = append(matches, device.ID)
			}
		}
		if len(matches) != 1 {
			return nil, nil, fmt.Errorf("device %s resolves to %d enabled resources", desired.Fingerprint, len(matches))
		}
		ids = append(ids, matches[0])
		desiredResult = append(desiredResult, signingDesiredDevice{
			Platform: desired.Platform, Fingerprint: desired.Fingerprint, NameSHA256: fingerprintReconcileName(desired.Name),
			ResourceID: matches[0], Status: string(asc.DeviceStatusEnabled),
		})
	}
	sortedIDs := append([]string(nil), ids...)
	sort.Strings(sortedIDs)
	return desiredResult, sortedIDs, nil
}

func writeVerifiedProfile(stateDir string, content []byte) (string, error) {
	parsed, err := decodeReconcileMobileProvision(content)
	if err != nil {
		return "", err
	}
	relative := profileOutputRelativePath(parsed.UUID)
	if relative == "" {
		return "", fmt.Errorf("profile UUID is unsafe")
	}
	root, err := rootfs.New(stateDir)
	if err != nil {
		return "", err
	}
	if err := root.MkdirAll("profiles", 0o700); err != nil {
		return "", err
	}
	existing, found, err := readOptionalBoundedRootFile(root, relative, reconcileProfileMaxBytes)
	if err != nil {
		return "", err
	}
	if found {
		existingDigest := sha256.Sum256(existing)
		contentDigest := sha256.Sum256(content)
		if existingDigest != contentDigest {
			return "", fmt.Errorf("profile %s already exists with different content", parsed.UUID)
		}
		return filepath.Join(stateDir, filepath.FromSlash(relative)), nil
	}
	if err := root.CreateNewFileAtomic(relative, content, 0o600); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, found, readErr := readOptionalBoundedRootFile(root, relative, reconcileProfileMaxBytes)
			if readErr == nil && found {
				existingDigest := sha256.Sum256(existing)
				contentDigest := sha256.Sum256(content)
				if existingDigest == contentDigest {
					return filepath.Join(stateDir, filepath.FromSlash(relative)), nil
				}
			}
		}
		return "", err
	}
	return filepath.Join(stateDir, filepath.FromSlash(relative)), nil
}

func readOptionalBoundedRootFile(root rootfs.Root, relative string, limit int64) ([]byte, bool, error) {
	file, err := root.OpenFile(relative)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if info.Size() > limit {
		return nil, false, fmt.Errorf("existing profile exceeds %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return nil, false, fmt.Errorf("existing profile exceeds %d bytes", limit)
	}
	return data, true, nil
}

func targetByBundleID(targets []signingTarget, bundleID string) (signingTarget, bool) {
	for _, target := range targets {
		if target.BundleID == bundleID {
			return target, true
		}
	}
	return signingTarget{}, false
}
