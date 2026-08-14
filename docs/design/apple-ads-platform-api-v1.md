# Apple Ads Platform API v1

## Goal

Add the complete Apple Ads Platform API v1 surface without changing the behavior of the existing Campaign Management API v5 commands during their deprecation window. Apple will retire v5 on January 26, 2027.

## Command placement

Platform API v1 commands live under `asc ads platform`. Existing direct resource commands under `asc ads` continue to call v5 until a later removal release.

Examples:

```bash
asc ads platform acls list --output json
asc ads platform campaigns find --ad-account "AD_ACCOUNT_ID" --file query.json
asc ads platform assets upload --ad-account "AD_ACCOUNT_ID" --file creative.png --brand "BRAND_ID"
asc ads platform api request --method GET --path v1/me
```

This keeps the incompatible request and response schemas explicit. It also gives every legacy command a precise replacement path instead of silently changing its API contract.

## API contract

- Base URL: `https://api.ads.apple.com/v1/`.
- OAuth token endpoint, client-secret JWT, and `searchadsorg` scope remain unchanged.
- Ad-account-scoped requests send `X-AP-Context: adAccountId=<id>;`.
- `GET /me`, `GET /acls`, `GET /orgs/{id}`, `GET /advertiser-resources`, and `POST /ad-accounts` omit `X-AP-Context`.
- The official clients omit context for shared-budget create, update, and delete, and make it optional for shared-budget view and query. The CLI follows that client contract because Apple's generated DocC parameter table conflicts with every official client and request example for these five operations.
- JSON endpoints accept a request file and preserve Apple's response envelope on stdout.
- Asset upload uses multipart form data with a rootfs-controlled local file.
- DELETE and state-changing recommendation apply or dismiss commands require `--confirm`.
- Comma-separated CLI values for query-string arrays are encoded as repeated wire keys.
- Errors and diagnostics go to stderr; usage failures exit with code 2.

## Authentication and configuration

Add an optional ad account ID beside the existing legacy organization ID:

- flag: `--ad-account`
- environment: `ASC_ADS_AD_ACCOUNT_ID`
- config/profile field: `ad_account_id`

Resolution keeps the existing profile and strict-auth rules. A v1 ad-account-scoped command resolves the explicit flag first, then the environment, then the selected profile. The root Ads config is used only when authentication does not select a named profile, so one profile cannot inherit another profile's ad account. Legacy v5 commands apply the same isolation to `--org`, `ASC_ADS_ORG_ID`, and `org_id`; profile-less access-token or environment authentication can still use the root `ads.org_id`.

## Endpoint coverage

Apple documents 99 v1 endpoints in 24 collections. The implementation is split by dependency and operator workflow:

1. Foundation, account management, app search, and app eligibility.
2. Campaigns, ad groups, geo targeting, keywords, negative keywords, ads, product pages, bulk operations, and budget orders.
3. Apple Maps brands, business categories, locations, location groups, creatives, and assets.
4. App and brand reports, insights, recommendations, suggestions, and change history.
5. Legacy v5 deprecation warnings and migration guidance.

The cumulative 4.4.0 stack implements all 99 operations. Its foundation layer registers 13 operations, the campaign layer adds 41, Maps and assets add 21, and reports and optimization add 24. The endpoint specs drive command registration. A separate checked-in contract fixture records method, path, parameters, SDK body optionality, response type, context requirement, confirmation, command path, and Apple source URL for all 99 operations. The final cumulative layer compares the implementation with that fixture and asserts exact count and uniqueness; earlier layers assert their implemented subsets.

## Compatibility and deprecation

The v1 host, context identifier, paths, payloads, response envelopes, pagination, reporting, and creative model are incompatible with v5. Reusing an existing command path would make a stable command change meaning based on a flag or release, so this design uses a separate `platform` namespace.

Every runnable v5 leaf remains available but gains:

- a `DEPRECATED:` direct-help prefix;
- one stderr warning per invocation;
- a v1 replacement command or an explicit statement when no one-command replacement exists;
- migration guidance in the Apple Ads command documentation.

No v5 command is removed in 4.4.0.

## Tests

RED-GREEN coverage includes:

- exact endpoint count, unique names and command paths, context metadata, path expansion, query encoding, body kind, and confirmation metadata;
- CLI registration, flags, required values, invalid values, unexpected arguments, stdout/stderr, and exit code 2;
- HTTP method, host, path, headers, repeated query parameters, JSON body, response preservation, and API errors;
- ad-account resolution across flag, environment, config, and named profiles with strict-auth isolation;
- raw v1 URL guardrails and context-free endpoint exceptions;
- multipart upload fields, content type, rootfs reads, file failures, and API failures;
- exact legacy warning text and direct-help migration paths;
- generated command docs and built-binary smoke tests.

The local repository gate is `make format`, `make check-docs`, `make lint`, and `ASC_BYPASS_KEYCHAIN=1 make test`.

## Handoff contract

Before any commit or push, run the full local repository gate above and keep
the endpoint fixture, generated command docs, and migration tests synchronized.
Live-account behavior remains the principal unverified risk: an operator with
real Apple Ads credentials must validate read-only Platform calls first, then
explicitly authorize any mutation testing. Never place those credentials in
the repository or test fixtures.

## Alternatives considered

An `--api-version` flag on the existing command tree would mix incompatible leaves and payload schemas in one help surface. Changing existing commands directly to v1 would break stable automation before the announced v5 retirement. A separate `platform` namespace is explicit today and leaves room to promote it after the deprecation window.
