# evize-app

A test application for [enclavize](https://github.com/hylswind/enclavize-workflow).

`setup.sh` at the repo root is the entire contract: when it is ready, it
listens on port 80 and answers `GET /healthz` with 200. The switch state
machine launches an instance, clones this repo at a commit, runs the script,
and once the load balancer in front sees `/healthz` answer, moves
`https://{domain}` to that instance and retires the one before it.

What it builds:

```
https://{domain}  ->  enclavize's front door (:443, its certificate)  ->  this instance, nginx on :80
```

Nothing in front of the instance is the application's. The balancer, the
certificate and the apex record are enclavize's, and one of the things probed
below is that the instance cannot touch them. Before `/healthz` exists the
balancer's checks are refused, which is what keeps traffic on the previous
version until this one is ready.

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
 "commit": "473542a6bdbec74ee3b52e8809b034f72b5ba7cf",
 "version": "2",
 "replaced": {"commit": "…", "instanceId": "i-…", "since": "…"},
 "probes": [{"name": "read the proof bucket", "expected": "deny",
             "verdict": "ok", "detail": "AccessDenied ..."}]}
```

`ok` is true only when every probe's verdict is `ok`. `version` is the
`VERSION` file, so two commits can be told apart by eye once switched; `replaced`
is what `/enclavize/apply/current` said when this instance started — the version
this one took over from.

## Probes

Must be refused: reading the proof bucket, writing the dashboard bucket,
deleting `enclavize-admin`, unlocking the console, listing registered domains,
rewriting `proof.{domain}`, creating a role without the boundary — and, around
the switch: repointing the apex, touching the front door, writing
`/enclavize/apply/pending`, terminating an instance wearing the enclave's name,
tagging itself with that name.

Must be permitted: reading what enclavize says is serving and coming, creating
its own bucket, describing its own instances, using Step Functions for itself —
the carve-outs that keep the boundary from being collateral damage rather than
a fence.

The probes are **real attempts, not policy simulation**. A simulated answer
models what IAM would decide; an attempt is what IAM did decide. The cost is
that a broken fence is genuinely breached rather than merely reported — which
is the right trade in a sacrificial account, where a silent hole is far worse.
The two probes that could do damage through a hole are shaped not to: the apex
is written back unchanged, and the terminate is a dry run.

A denial has to look like one. A probe that fails for some other reason — a
missing resource, a bad argument — is reported **UNCLEAR** and fails the page,
because it proves nothing about the fence.

## Cleanup

`teardown.sh` removes what `setup.sh` created and enclavize does not: the
bucket, and any instance still carrying the app's tag. enclavize's own teardown
handles the front door and every instance it launched; `tests/e2e/unseal.py`
runs this first.

Everything created here is tagged `evize:app=test`, and the script ends by
reporting anything still carrying that tag — which would mean `setup.sh` has
grown something the teardown does not know about yet:

```bash
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=evize:app,Values=test \
  --query 'ResourceTagMappingList[].ResourceARN'
```

A genuinely sealed account has no credential that can run any of this, so
cleanup goes either through another applied commit or through a rescue root key
kept deliberately for the purpose.

## Redeploying

Apply another commit. enclavize launches it behind the front door, waits for
`/healthz`, switches, and retires this instance. Nothing here has to retire
anything: the previous version is enclavize's to take out, and it does so only
after the new one is in.
