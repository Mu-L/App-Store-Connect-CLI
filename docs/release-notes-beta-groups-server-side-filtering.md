# TestFlight beta groups server-side filtering release note

`asc testflight groups list --app APP_ID --internal` and `--external` are now
filtered by App Store Connect instead of in the CLI. `GET /v1/apps/{id}/betaGroups`
accepts only a page limit, so the command previously fetched every page, filtered
the aggregate in Go, truncated it to `--limit`, and printed
`Warning: showing N of M filtered groups`. Those requests now go to
`GET /v1/betaGroups` with `filter[app]` and `filter[isInternalGroup]`, and the
warning is gone.

Two new flags cover query parameters that endpoint already documents: `--name`
filters on the exact group name (`filter[name]`) and `--sort` accepts `name`,
`-name`, `createdDate`, `-createdDate`, `publicLinkEnabled`,
`-publicLinkEnabled`, `publicLinkLimit`, and `-publicLinkLimit`. An unsupported
`--sort` value is a usage error listing the valid values.

## Migration

A filtered app-scoped listing now returns one page, matching what
`--global --internal` has always done. Add `--paginate` to keep collecting every
matching group:

```bash
# Before: implicitly walked every page.
asc testflight groups list --app APP_ID --internal

# After: same complete result.
asc testflight groups list --app APP_ID --internal --paginate
```

When more pages exist, the command prints the standard
`more pages exist (use --paginate or --next where supported)` hint on stderr, so
an unmigrated invocation reports that its result is partial rather than
silently returning less.

`--limit` on a filtered listing is now the page size of matching groups rather
than a cap applied after the CLI filtered everything it fetched. Callers that
used `--limit` to bound a filtered result keep working and no longer pay for a
complete walk through all pages.

`--next` now rejects `--internal`, `--external`, `--name`, and `--sort`. A
`links.next` URL is followed verbatim and already carries the query it came
from, so those flags were previously accepted and discarded. Drop them from the
follow-up call; a bare `--next`, with or without `--paginate`, is unchanged.

Unfiltered app-scoped listing (`--app APP_ID` with no filter or sort) still uses
`GET /v1/apps/{id}/betaGroups` and is unchanged.
