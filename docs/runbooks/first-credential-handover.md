# Handing a Person Their First Credential

A person a provider creates holds no password and cannot sign in. A provider issues a temporary
password, shown once, and hands it to the person (`ADR-IAM-010` §5.4,
`TDD-identity-control-005` 2.12.0 §A First Credential).

## Starts from

- A new person, created in the Admin Portal (`POST /v1/principals`), who has never signed in.
- A person whose temporary password lapsed unused: the service logs `a temporary password lapsed
  unused and was removed`, naming the issuance and the Principal.
- A person who lost the value before using it.

## Steps

1. **Verify the person first,** in person or on a live call, as assisted recovery does
   (`ADR-IAM-005 §5.5`). A request in a ticket or an email is not verification.
2. **Issue.** In the Admin Portal, on the person's page: **Issue a temporary password**, with a reason.
   The route is `POST /v1/principals/{principal_id}:issue-temporary-password` (`Idempotency-Key`,
   `X-Administrative-Reason`, `aal2` within 5 minutes). The value is shown once and lapses after 24
   hours unused.
3. **Hand it over on a channel other than the one that carries the username.** Never in a ticket, a
   chat log, or an email that also carries the username. Read it out on the call, or send it on a
   second channel. Do not keep a copy; clear the clipboard.
4. **The person signs in** with the username and the value. The kernel requires a new password at
   once and refuses the temporary value as the new one. A sign-in to the Admin Portal then enrolls a
   TOTP authenticator and recovery codes.

## What can go wrong

| Answer or signal | Meaning | Do |
| :-- | :-- | :-- |
| `409`, detail `credential-established` | The person has set a password of their own | Nothing here issues one. A lost password is not recovered by this route (`ADR-IAM-010 §6`) |
| `200` with no `value` | A retry with the same `Idempotency-Key`: the value is never kept | Issue again with a new key; it replaces the first |
| The value was lost, or lapsed | It was never stored, so it cannot be looked up | Issue again; the earlier issuance is recorded `replaced` or `lapsed` |
| More than one issuance for a Principal in a day | A signal (`ADR-IAM-010 §6`) | Ask the issuing provider why, from the issuances' reasons |
| The person says the value was refused at first sign-in, and they did not use it | Someone else may have signed in first | Suspend the Principal (`:suspend`) and follow assisted recovery |

## Records

Each issuance is in `identity.temporary_password_issuance` (who, why, when, when it lapses) and its end
in `identity.temporary_password_outcome` (`used`, `lapsed`, `replaced`, `failed`), both insert-only,
with a `privileged_access` row `temporary_password.issue`. None holds the value. The person is told of
the issuance, as a password bound by an administrator, at their notification addresses.
