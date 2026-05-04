# Add Google SSO for the SMB tier

## What

We currently support email + password auth for all tiers, and SAML SSO for
the Enterprise tier. We want to add **Google OAuth SSO** as a sign-in option
for our **SMB tier** (free + paid plans up to 50 seats).

Users on the SMB tier should be able to:
- Sign in with their Google Workspace account
- Link an existing email/password account to a Google identity
- Be auto-provisioned a workspace when their domain is recognised

## Why

- Reduce friction in SMB self-serve signup (current free→paid conversion
  is bottlenecked at the password-creation step; analytics show ~28% drop
  off there).
- Unblock the Q3 sales motion targeting Google-Workspace-native SMBs.
- Internal data: 64% of SMB signups already use a `@gmail.com` or
  Google-Workspace-domain email, so the addressable share is large.

## Scope

- **In scope:** Google OAuth via OIDC. Account linking flow. Domain auto-
  provisioning for new workspaces.
- **Out of scope (this iteration):** Microsoft / Apple / Okta SSO; SAML for
  the SMB tier (Enterprise stays SAML-only); SCIM provisioning.
- **Existing constraints:** auth middleware is currently JWT-only and
  assumes one identity provider per user. Account-linking will require
  a refactor to support multiple identities per user.

## Constraints

- Existing email/password auth must continue working unchanged.
- SMB tier has no admin / IT contact — flow must be self-serve, no
  domain-verification step requiring DNS access.
- Free tier already has password auth; users with an existing free account
  using the same email must be able to upgrade to Google SSO without
  losing their workspace state.
- Compliance: SOC2 audit log must record SSO sessions identically to
  password sessions.
- We have a Q3 sales kickoff on Sept 22 — leadership has asked for the
  feature to be GA by then.

## What success looks like

- ≥30% of new SMB signups in the 30 days after launch use Google SSO.
- Free→paid conversion in the SMB tier improves by ≥5pp.
- No security incidents related to account-linking misuse.
- Support team can resolve account-linking failures self-serve from
  documented flows in <10 minutes.
