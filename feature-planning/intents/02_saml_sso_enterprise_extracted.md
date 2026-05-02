# Add SAML SSO support for Enterprise customers

## What

Add a SAML 2.0 single sign-on option for the Enterprise tier so workspace admins can configure SAML metadata, enable just-in-time user provisioning, map groups to roles from IdP attributes, force SSO by disabling email/password for a workspace, and record SSO-related activity in audit logs.

## Why

Enterprise customers want to use their existing identity providers to centrally manage access, and the lack of SAML has caused lost deals and blocked prospects where SAML is a contract requirement.

## Scope

- **In scope:** SAML 2.0 only for Enterprise, admin configuration of SAML metadata via URL or XML upload, just-in-time user provisioning on first login, group-based role mapping from IdP attributes, forced SSO mode that disables email/password for a workspace, audit log entries for SSO config changes and SSO sessions, self-serve admin UI for SAML config, Okta/OneLogin/Azure AD tested as primary IdPs
- **Out of scope:** OIDC for Enterprise, SCIM provisioning, multi-IdP per workspace, service provider initiated SSO from custom domains, custom domain SP-initiated SSO
- **Existing constraints:** Current auth middleware assumes a single OIDC identity per user after the Google SSO work in #3801; SAML adds a second IdP class and may require extending the identity model or enforcing one SSO type per workspace. The audit log schema in #4112 covers user-action events but not workspace-config-change events.

## Constraints

- This is a SOC2-relevant change.
- Audit log parity with email/password sessions is a hard requirement.
- GA-or-late-beta announcement is desired by Oct 28 for Q4 sales kickoff.

## What success looks like

- Enterprise customers can authenticate using SAML 2.0 with their existing IdP.
- Workspace admins can configure SAML without assistance through a self-serve UI.
- Users can be provisioned automatically on first SSO login.
- Role assignment can be driven from IdP group attributes.
- Admins can disable email/password login for a workspace to force SSO.
- SSO configuration changes and SSO sessions appear in audit logs.
- Okta, OneLogin, and Azure AD are verified as working primary IdPs.

---

_Extracted from GitHub issue https://github.com/example/platform/issues/4287 (extraction confidence: high)._

_Fields needing clarification: Whether forced SSO mode applies to all users in a workspace or has exceptions., Whether SAML metadata URL and XML upload are both required at launch or either is sufficient., Whether the feature must support IdP-initiated login flows only at launch or also any partial SP-initiated behavior., Whether there are any specific performance, accessibility, or localization requirements., Whether exact GA versus late-beta timing is a hard deadline or a preference.._
