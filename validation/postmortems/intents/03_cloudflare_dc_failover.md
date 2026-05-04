# Fail over the control plane from primary datacenter PDX-01 to backup DC

## What

PDX-01 (our primary datacenter, Hillsboro Oregon) has just lost utility
power. Generators are running but utility may not be restored for 12-24
hours. We need to fail over the control plane and analytics services
that primary out of PDX-01 to our secondary datacenter to keep the
control plane reachable for customers.

The data plane (edge / proxy) is unaffected — customer traffic continues
flowing through our 285+ POPs as normal. This rollout is specifically
about restoring the **control plane and analytics** stack.

## Why

The dashboard, API, terraform-provider, analytics ingestion and
analytics query path all primary out of PDX-01. With PDX-01's power
unstable, we cannot trust that those services will stay up — we need to
move them.

## Scope

- ~50 distinct services constitute the control plane stack. The
  authoritative service catalogue lists the HA configuration of each.
- Most services are documented as "highly available across multiple
  facilities." Some are not.
- We have a documented runbook for each service's failover procedure.
- We have access to the secondary DC; capacity has been verified.

## Constraints

- Customer-visible: every minute of dashboard / API downtime is
  noticed and escalated. Analytics gaps are also user-visible.
- Service catalogue may not match reality — some services that claim
  HA may have grown undocumented dependencies on PDX-01-only state.
- Failover order matters: dependencies between services mean the
  catalogue's claimed independence may not hold.
- There has been no full failover drill in over 12 months.
- Time pressure: PDX-01 power is unstable RIGHT NOW.

## What success looks like

Control plane and analytics restored within hours. Customers experience
brief degradation but no extended outage. No data loss in analytics or
configuration state.

---

_Real-world echo: pre-incident framing of the **Cloudflare November 2-4,
2023 control plane outage**, which lasted 41 hours because many control
plane services were not actually HA-deployed across multiple facilities
despite the catalogue claiming so, and there had not been a recent
full-failover drill._
