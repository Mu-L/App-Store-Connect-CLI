# Official search optimization plan

Release 4.4.4 adds an experimental, read-only workflow that turns official
Apple Ads Platform API v1 evidence and App Store Connect metadata into one
reviewable search plan:

```bash
asc optimize search plan \
  --app "APP_ID" \
  --version "4.4.4" \
  --ad-account "AD_ACCOUNT_ID" \
  --country "US" \
  --genre "PRODUCTIVITY_UTILITIES" \
  --locale "en-US" \
  --out-dir ".asc/optimization/4.4.4" \
  --output markdown
```

The command keeps Apple's metrics semantically separate: popularity is market
search demand, impression share is app-specific paid reach, search-term report
rows are actual paid outcomes, and metadata coverage comes from the selected
App Store localization. Deterministic actions identify converting broad terms,
costly zero-install terms, metadata candidates, low-share opportunities, and
already-saturated terms without inventing organic rank or proprietary
difficulty scores.

When `--out-dir` is set, the command writes a canonical report plus review-only
metadata, exact-keyword, and negative-keyword import files. It never applies
those files or mutates campaigns or App Store metadata. Partial Apple Ads
source failures remain visible in the report, while successful official data
is preserved.

App Store Connect and Apple Ads credentials are independent. Run `asc auth`
for App Store Connect and `asc ads auth login` for Apple Ads before using the
workflow. Credentialed live verification is still recommended before relying
on generated candidates in production.
