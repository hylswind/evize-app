# evize-app

A test application for [enclavize](https://github.com/hylswind/evize-workflow).

`setup.sh` at the repo root is the entire contract. The deploy state machine
launches an instance, clones this repo at a commit, and runs it.

What it builds:

```
app.{domain}  ->  ALB (:443, its own certificate)  ->  an instance running nginx
                     :80 redirects to :443
```

The certificate is the application's own. enclavize's covers `dashboard.`,
`proof.` and `apply.` — its names, not this one — so HTTPS here means asking
ACM for a certificate and writing validation records under `app.{domain}`.
That is the half of the DNS carve-out that claiming the name does not
exercise: the boundary has to permit `_hash.app.{domain}` as well as
`app.{domain}`, while still refusing the three names enclavize keeps.

It is requested once and reused. Asking per deploy would leave a trail of
certificates and pay the validation wait every time.

What the page shows: the result of **probing the permission boundary from inside
the sealed account**. Everything else asserted about that boundary is asserted
against a policy document — this is the only place IAM itself answers.

Green means every forbidden action was refused and every needed one permitted.
A red **HOLE** row means the boundary allowed something it should not.

Beside the page, `results.json` carries the same probes as data, in the shape
enclavize's end-to-end suite reads — so a test can assert on the outcome instead
of scraping the page:

```json
{"ok": true,
 "probes": [{"name": "read the proof bucket", "expected": "deny",
             "verdict": "ok", "detail": "AccessDenied ..."}]}
```

`ok` is true only when every probe's verdict is `ok`.

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

`teardown.sh` removes everything `setup.sh` created. enclavize's own teardown
handles what enclavize built; only the application knows what the application
built, which is why this lives here. `tests/e2e/unseal.py` runs it first, while
the hosted zone still exists for `app.{domain}` to be deleted from.

The order matters and the script keeps it: record, listener, load balancer (wait
for it to actually disappear), target group, instances, security groups, bucket.
A security group will not go while anything still references it, and deletion is
not instant. It is safe to run twice.

Everything created here is tagged `evize:app=test`, and the script ends by
reporting anything still carrying that tag — which would mean `setup.sh` has
grown something the teardown does not know about yet:

```bash
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=evize:app,Values=test \
  --query 'ResourceTagMappingList[].ResourceARN'
```

Route 53 record sets are the exception — AWS allows tags only on hosted zones
and health checks — so `app.{domain}` is deleted by name.

A genuinely sealed account has no credential that can run any of this, so
cleanup goes either through another applied commit or through a rescue root key
kept deliberately for the purpose.

## Redeploying

The ALB, target group and certificate are reused rather than rebuilt, so
`app.{domain}` keeps pointing at the same load balancer and only the registered
target changes. Each deploy replaces the previous instance in the target group,
terminates it, and re-runs the probes.

Retiring it is the application's job. enclavize launches one instance per apply
and hands it over; it has no view on whether a previous one is still wanted, so
nothing else will stop it. Left alone they accumulate one per commit applied.
