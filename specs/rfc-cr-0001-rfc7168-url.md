# RFC-CR-0001: Correct the RFC 7168 metadata URL

> Internal CPIP Request for Change. This is not an IETF RFC or protocol standard.

| Field | Value |
| --- | --- |
| Status | Implemented |
| Requester / owner | CPIP documentation maintainers |
| Opened / implemented | 15 October 2026 |
| Affected component | `pyproject.toml`, `[project.urls]` |
| Related CPIP record | Specs/reference index |

## Current behavior

The `RFC-7168` project URL pointed to RFC 2168, a different RFC.

## Proposed behavior

Point `RFC-7168` to the RFC Editor’s canonical RFC 7168 page:
<https://www.rfc-editor.org/rfc/rfc7168>.

## Verification

- Parsed `pyproject.toml` with Python `tomllib`.
- Confirmed the `RFC-7168` URL terminates in `/rfc7168`.
- No runtime behavior or dependency changed.

## Release record

Implemented in commit `0a6d0f9` (`docs: add feature and change request records`).

## Reference

I. Nazar, [RFC 7168: The Hyper Text Coffee Pot Control Protocol for Tea Efflux Appliances](https://www.rfc-editor.org/rfc/rfc7168), 1 April 2014, Informational; updates RFC 2324.
