# evize-app

A test application for [enclavize](https://github.com/hylswind/evize-workflow).

`setup.sh` at the repo root is the entire contract. The deploy state machine
launches an instance, clones this repo at a commit, and runs it.

What it builds:

```
app.{domain}  ->  ALB (:80)  ->  the deploy instance running nginx
```

What the page shows: the result of **probing the permission boundary from inside
the sealed account**. Everything else asserted about that boundary is asserted
against a policy document — this is the only place IAM itself answers.

Green means every forbidden action was refused and every needed one permitted.
A red **HOLE** row means the boundary allowed something it should not.

## Probes

Must be refused: reading the proof bucket, writing the dashboard bucket,
deleting `enclavize-admin`, unlocking the console, listing registered domains,
rewriting `proof.{domain}`, creating a role without the boundary.

Must be permitted: creating its own bucket, describing its own instances, using
Step Functions for itself — the carve-outs that keep the boundary from being
collateral damage rather than a fence.

The probes are **real attempts, not policy simulation**. A simulated answer
models what IAM would decide; an attempt is what IAM did decide. The cost is
that a broken fence is genuinely breached rather than merely reported — which
is the right trade in a sacrificial account, where a silent hole is far worse.

`app.{domain}` is itself a probe: the boundary protects `dashboard.`, `proof.`
and the apex MX/NS/SOA while leaving the rest of the zone to the application.
The page being reachable at all is that carve-out working.

## Cleanup

Everything created here is tagged `evize:app=test`:

```bash
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=evize:app,Values=test \
  --query 'ResourceTagMappingList[].ResourceARN'
```

Route 53 record sets are the exception — AWS allows tags only on hosted zones
and health checks — so `app.{domain}` has to be deleted by name.

Delete in this order, or the security groups will refuse to go: listener, load
balancer (wait for it to disappear), target group, security groups, buckets.

A genuinely sealed account has no credential that can do any of this, so
cleanup either goes through another deploy or through a rescue root key kept
deliberately for the purpose.

## Redeploying

The ALB and target group are reused rather than rebuilt, so `app.{domain}` keeps
pointing at the same load balancer and only the registered target changes. Each
deploy replaces the previous instance in the target group and re-runs the probes.
