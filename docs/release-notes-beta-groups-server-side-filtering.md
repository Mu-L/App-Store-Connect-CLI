# TestFlight beta groups server-side filtering release note

`asc testflight groups list --app APP_ID --internal` and `--external` are now
filtered by App Store Connect instead of in the CLI. `GET /v1/apps/{id}/betaGroups`
accepts only a page limit, so the command previously fetched every page and
filtered the aggregate in Go. Those requests now go to `GET /v1/betaGroups`
with `filter[app]` and `filter[isInternalGroup]`, while retaining the complete
multi-page result.

Two new experimental flags cover query parameters that endpoint already
documents: `--name` filters on the exact group name (`filter[name]`) and
`--sort` accepts `name`, `-name`, `createdDate`, `-createdDate`, `publicLinkEnabled`,
`-publicLinkEnabled`, `publicLinkLimit`, and `-publicLinkLimit`. An unsupported
`--sort` value is a usage error listing the valid values.

## Pagination compatibility

App-scoped `--internal` and `--external` listings continue to collect every
matching page automatically, so existing invocations retain complete output:

```bash
asc testflight groups list --app APP_ID --internal
```

App-scoped listings that use only the new `--name` or `--sort` flags follow the
standard one-page default; add `--paginate` to collect all matching pages.
Global listings are unchanged and also require `--paginate` for aggregation.

`--limit` on a filtered listing is now the page size of matching groups rather
than a cap applied after the CLI filtered everything it fetched.

`--next` now rejects `--internal`, `--external`, `--name`, and `--sort`. A
`links.next` URL is followed verbatim and already carries the query it came
from, so those flags were previously accepted and discarded. Drop them from the
follow-up call; a bare `--next`, with or without `--paginate`, is unchanged.

Unfiltered app-scoped listing (`--app APP_ID` with no filter or sort) still uses
`GET /v1/apps/{id}/betaGroups` and is unchanged.
