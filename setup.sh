#!/bin/bash
#
# The whole contract enclavize requires of an application: an executable
# setup.sh at the repo root that, when ready, listens on port 80 and answers
# GET /healthz with 200. The switch state machine launches an instance, clones
# this repo at a commit, runs this — and once the load balancer in front sees
# /healthz answer, moves https://{domain} to this instance and retires the one
# before it.
#
# This one serves a page, and what the page shows is the result of probing the
# permission boundary from inside the sealed account. Everything asserted about
# that boundary elsewhere is asserted against a policy document; this is the
# only place IAM itself answers.
#
# Nothing here builds a front door of its own. The balancer, the certificate
# and the apex record are enclavize's, and one of the things probed below is
# that this instance cannot touch them.
#
# Every resource created here is tagged evize:app=test so it can be found and
# deleted afterwards.

set -uo pipefail

# enclavize hands an application one thing: the domain. Not the region,
# because enclavize only ever runs in us-east-1; not the commit, because
# this repo is already checked out at it.
DOMAIN="${ENCLAVIZE_DOMAIN:-}"
REGION=us-east-1
export AWS_DEFAULT_REGION="$REGION"   # for the calls below that take no --region
COMMIT="$(git rev-parse HEAD)"
VERSION="$(cat VERSION 2>/dev/null || echo unknown)"
DEPLOYED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RESULTS=/tmp/probe-results.tsv
WEB=/usr/share/nginx/html

log() { echo "[app] $*"; }
: > "$RESULTS"

# --- a CLI that knows every service it is asked about -----------------------
#
# The probes below are only as good as the CLI running them. The one the image
# ships lags the newer services — it has never heard of `signin` — and a
# command the CLI refuses to parse never reaches IAM, so it proves nothing
# about the boundary. The current release, installed the way AWS documents.

dnf install -y unzip >/dev/null 2>&1
curl -sSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip \
  && unzip -qo /tmp/awscliv2.zip -d /tmp \
  && /tmp/aws/install --update >/dev/null 2>&1
export PATH=/usr/local/bin:$PATH
hash -r
log "aws cli: $(aws --version 2>&1)"

# --- who and where are we -------------------------------------------------

TOKEN="$(curl -sX PUT http://169.254.169.254/latest/api/token \
          -H 'X-aws-ec2-metadata-token-ttl-seconds: 600')"
imds() { curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$1"; }
INSTANCE_ID="$(imds instance-id)"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

log "account=$ACCOUNT instance=$INSTANCE_ID commit=$COMMIT version=$VERSION"

# --- what enclavize says ---------------------------------------------------
#
# The one channel an applied version has: two parameters it can read and not
# write. `current` names what was serving when this instance started — the
# version this one replaces, if any. `pending` is written when a later apply
# is accepted, and says which commit is coming and when; nothing is pending
# while this instance is the one being switched in.

PREVIOUS="$(aws ssm get-parameter --name /enclavize/apply/current \
             --query Parameter.Value --output text 2>/dev/null || echo "")"
[ "$PREVIOUS" = "None" ] && PREVIOUS=""
log "replacing: ${PREVIOUS:-nothing}"

# --- probe the boundary ---------------------------------------------------
#
# Real attempts, not policy simulation. A simulated answer models what IAM
# would decide; an attempt is what IAM did decide. The cost is that a broken
# fence is actually breached rather than merely reported — acceptable in a
# sacrificial account, where a silent hole is the worse outcome by far.
#
# A denial has to look like one. A command that fails for some other reason —
# a thing that does not exist, a bad argument — proves nothing about the
# fence, and is reported as UNCLEAR rather than counted as refused.

probe() {                       # probe <expectation> <label> <command...>
  local expect="$1" label="$2"; shift 2
  local output verdict
  # A dry run that would have gone ahead fails too, with DryRunOperation —
  # which for the purpose here is the call being allowed.
  if output="$("$@" 2>&1)" || echo "$output" | grep -q DryRunOperation; then
    [ "$expect" = allow ] && verdict=ok || verdict=HOLE
  elif echo "$output" | grep -qE 'AccessDenied|UnauthorizedOperation|not authorized'; then
    [ "$expect" = deny ] && verdict=ok || verdict=BLOCKED
  else
    verdict=UNCLEAR
  fi
  printf '%s\t%s\t%s\t%s\n' "$verdict" "$expect" "$label" \
    "$(echo "$output" | tr '\n' ' ' | cut -c1-160)" >> "$RESULTS"
  log "$label -> $verdict"
}

ZONE_ID="$(aws route53 list-hosted-zones-by-name --dns-name "$DOMAIN" \
            --query 'HostedZones[0].Id' --output text 2>/dev/null | sed 's|/hostedzone/||')"
FRONT_DOOR="$(aws elbv2 describe-load-balancers --names enclavize-app \
               --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || echo "")"
# The apex record as it stands, so the probe below can try to write it back
# unchanged: a hole would then do no damage.
APEX_A="$(aws route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" \
           --query "ResourceRecordSets[?Name=='$DOMAIN.' && Type=='A']|[0]" --output json 2>/dev/null)"

# Things the enclave must refuse.
probe deny "read the proof bucket" \
  aws s3api list-objects-v2 --bucket "enclavize-proof-$ACCOUNT"
probe deny "write the dashboard bucket" \
  aws s3api put-object --bucket "enclavize-dashboard-$ACCOUNT" --key tampered
probe deny "delete the admin role" \
  aws iam delete-role --role-name enclavize-admin
probe deny "unlock the console" \
  aws signin delete-console-authorization-configuration --target-id "$ACCOUNT" --region us-east-1
probe deny "list registered domains" \
  aws route53domains list-domains --region us-east-1
probe deny "rewrite proof.$DOMAIN" \
  aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" \
    --change-batch "{\"Changes\":[{\"Action\":\"UPSERT\",\"ResourceRecordSet\":{\"Name\":\"proof.$DOMAIN\",\"Type\":\"TXT\",\"TTL\":60,\"ResourceRecords\":[{\"Value\":\"\\\"hijacked\\\"\"}]}}]}"
probe deny "create an unbounded role" \
  aws iam create-role --role-name evize-app-escape \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# The switch, which an applied version must not be able to work around.
probe deny "repoint the apex at something else" \
  aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" \
    --change-batch "{\"Changes\":[{\"Action\":\"UPSERT\",\"ResourceRecordSet\":$APEX_A}]}"
probe deny "touch the front door" \
  aws elbv2 add-tags --resource-arns "$FRONT_DOOR" --tags Key=evize,Value=hijacked
probe deny "tell enclavize what is coming" \
  aws ssm put-parameter --name /enclavize/apply/pending --value hijacked --type String --overwrite
probe deny "terminate an enclave instance" \
  aws ec2 terminate-instances --dry-run --instance-ids "$INSTANCE_ID"
probe deny "wear the enclave's name" \
  aws ec2 create-tags --resources "$INSTANCE_ID" --tags Key=Name,Value=enclavize-impostor

# Things the application legitimately needs.
probe allow "read what enclavize says is serving and coming" \
  aws ssm get-parameters-by-path --path /enclavize/apply
probe allow "create my own bucket" \
  aws s3api create-bucket --bucket "evize-app-$ACCOUNT" --region "$REGION"
probe allow "describe my own instances" \
  aws ec2 describe-instances --region "$REGION"
probe allow "use step functions for myself" \
  aws stepfunctions list-state-machines --region "$REGION"

aws s3api put-bucket-tagging --bucket "evize-app-$ACCOUNT" \
  --tagging "TagSet=[{Key=evize:app,Value=test},{Key=evize:commit,Value=$COMMIT}]" 2>/dev/null || true

# --- serve the results ----------------------------------------------------

log "installing nginx"
dnf install -y nginx >/dev/null 2>&1
HOLES="$(grep -c $'^HOLE\t' "$RESULTS" || true)"
BLOCKED="$(grep -c $'^BLOCKED\t' "$RESULTS" || true)"
UNCLEAR="$(grep -c $'^UNCLEAR\t' "$RESULTS" || true)"

{
  cat <<'HEAD'
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>evize-app</title>
<style>
  :root { color-scheme: light dark; --ink:#111; --paper:#fff; --line:#0002; }
  @media (prefers-color-scheme: dark) { :root { --ink:#f2f2f2; --paper:#0d0d0d; --line:#fff3; } }
  body { margin:0; padding:2rem 1rem; background:var(--paper); color:var(--ink);
         font:16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width:60rem; margin:0 auto; }
  h1 { font-size:1.6rem; margin:0 0 .25rem; letter-spacing:-.02em; }
  .sub { opacity:.65; margin:0 0 2rem; font-size:.9rem; }
  .verdict { padding:.9rem 1.1rem; border-radius:.5rem; margin-bottom:2rem; font-weight:600; }
  .pass { background:#0a04; } .fail { background:#f004; }
  table { width:100%; border-collapse:collapse; font-size:.9rem; }
  th { text-align:left; font-weight:600; opacity:.6; padding:.5rem .6rem; border-bottom:1px solid var(--line); }
  td { padding:.55rem .6rem; border-bottom:1px solid var(--line); vertical-align:top; }
  .ok { color:#0a7; } .hole { color:#e33; font-weight:700; } .blocked { color:#c80; font-weight:700; }
  .unclear { color:#c80; }
  .why { opacity:.5; font-size:.8rem; font-family:ui-monospace, monospace; }
  dl { display:grid; grid-template-columns:auto 1fr; gap:.3rem 1rem; font-size:.85rem; opacity:.7; margin-top:2.5rem; }
  dt { font-weight:600; }
  dd { margin:0; font-family:ui-monospace, monospace; }
</style>
<main>
HEAD

  echo "<h1>permission boundary · version $VERSION</h1>"
  echo "<p class=sub>probed from inside the sealed account, by the application itself</p>"

  if [ "$HOLES" -gt 0 ]; then
    echo "<div class='verdict fail'>$HOLES hole(s): the boundary permitted something it should refuse.</div>"
  elif [ "$BLOCKED" -gt 0 ]; then
    echo "<div class='verdict fail'>$BLOCKED over-restriction(s): the application was denied something it needs.</div>"
  elif [ "$UNCLEAR" -gt 0 ]; then
    echo "<div class='verdict fail'>$UNCLEAR probe(s) failed for a reason that says nothing about the boundary.</div>"
  else
    echo "<div class='verdict pass'>The boundary held. Everything forbidden was refused; everything needed was permitted.</div>"
  fi

  echo "<table><tr><th>probe</th><th>expected</th><th>result</th><th>what AWS said</th></tr>"
  while IFS=$'\t' read -r verdict expect label detail; do
    case "$verdict" in
      ok)      cls=ok;      word=$([ "$expect" = deny ] && echo "denied" || echo "allowed") ;;
      HOLE)    cls=hole;    word="ALLOWED — HOLE" ;;
      BLOCKED) cls=blocked; word="DENIED — too strict" ;;
      UNCLEAR) cls=unclear; word="failed — not a denial" ;;
    esac
    echo "<tr><td>$label</td><td>$expect</td><td class=$cls>$word</td><td class=why>$(echo "$detail" | sed 's/&/\&amp;/g; s/</\&lt;/g')</td></tr>"
  done < "$RESULTS"
  echo "</table>"

  cat <<FOOT
<dl>
  <dt>account</dt><dd>$ACCOUNT</dd>
  <dt>version</dt><dd>$VERSION</dd>
  <dt>commit</dt><dd>$COMMIT</dd>
  <dt>instance</dt><dd>$INSTANCE_ID</dd>
  <dt>deployed</dt><dd>$DEPLOYED_AT</dd>
  <dt>replaced</dt><dd>${PREVIOUS:-nothing}</dd>
</dl>
</main>
FOOT
} > "$WEB/index.html"

# The same probes as machine-readable data, in the shape enclavize's e2e suite
# reads. The page above is for a person; this is so a test can assert on the
# result instead of scraping HTML. python3 rather than hand-rolled quoting:
# `detail` is whatever AWS said, and that contains quotes and backslashes.
python3 - "$RESULTS" "$ACCOUNT" "$COMMIT" "$VERSION" "$INSTANCE_ID" "$DEPLOYED_AT" "$PREVIOUS" <<'PY' \
  > "$WEB/results.json"
import csv, json, sys

path, account, commit, version, instance, deployed_at, previous = sys.argv[1:8]
with open(path, newline="") as handle:
    probes = [
        {"name": label, "expected": expect, "verdict": verdict, "detail": detail}
        for verdict, expect, label, detail in csv.reader(handle, delimiter="\t")
    ]

json.dump({
    "ok": all(p["verdict"] == "ok" for p in probes),
    "account": account,
    "commit": commit,
    "version": version,
    "instance": instance,
    "deployedAt": deployed_at,
    "replaced": json.loads(previous) if previous else None,
    "probes": probes,
}, sys.stdout, indent=2)
sys.stdout.write("\n")
PY

# --- ready ----------------------------------------------------------------
#
# /healthz is a file, and the last thing written: it does not exist until
# everything above has, and nginx does not listen until it does. Before this
# line the load balancer's checks are refused, which is what keeps traffic on
# the version before this one.

echo ok > "$WEB/healthz"
systemctl enable --now nginx >/dev/null 2>&1
log "listening on 80; /healthz answers"
log "done — https://$DOMAIN once the switch reaches this instance"
log "holes=$HOLES over-restrictions=$BLOCKED unclear=$UNCLEAR"
