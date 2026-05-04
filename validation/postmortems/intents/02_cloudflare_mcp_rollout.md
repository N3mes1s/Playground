# Roll out updated MCP/BGP routing config to all 19 spine locations

## What

We have an updated routing configuration for our anycast network that
reaches our 19 MCP-enabled spine locations. This change adjusts how our
spine routers announce certain prefixes upstream and affects every
customer using any service that transits these spines.

We will use our standard stepped-rollout procedure: deploy to a small
batch, observe, then expand to the rest if the small batch looks healthy.

## Why

The current configuration is inefficient and is causing minor
asymmetries in upstream traffic during peak hours. The new config has
been validated in the lab and on a single canary location for 72 hours
without incident.

## Scope

- 19 spine locations.
- Standard `routing-deploy` tool with `--batch-size N` and `--wait
  <seconds>` flags.
- Change-request ticket with peer review by two senior network engineers.
- Dry-run output reviewed in the ticket.

## Constraints

- Customer-visible: any incorrect propagation could black-hole traffic
  for one or more regions globally — i.e. a global outage is the worst
  case.
- Routing changes are eventually consistent across the network and not
  trivially reversible at the same speed they roll out.
- The peer review and dry-run step is required by policy; both have been
  completed.
- Time pressure: the asymmetry is causing observable customer reports
  via support, so leadership wants a fix this week.

## What success looks like

All 19 spine locations on the new config, traffic asymmetry resolved,
no customer-reported regressions during or after the rollout.

---

_Real-world echo: pre-incident framing of the **Cloudflare June 21, 2022
outage**, in which the rollout reached MCP-enabled locations and
"swiftly took these 19 locations offline" because the rollout steps
"weren't small enough to catch the error before it hit all of our
spines." Peer review and dry-run had been completed but the staged
rollout granularity was the gap._
