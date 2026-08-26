#!/bin/bash
#
# The whole contract enclavize requires of an application: an executable
# setup.sh at the repo root. The deploy state machine launches an instance,
# clones this repo at a commit, and runs this.
#
# This one serves a page over HTTPS, behind an ALB, at app.{domain} — and what
# the page shows is the result of probing the permission boundary from inside
# the sealed account. Everything asserted about that boundary elsewhere is
# asserted against a policy document; this is the only place IAM itself answers.
#
# The certificate is the application's own. enclavize's covers dashboard.,
# proof. and apply. — its names, not this one — so getting HTTPS at all means
# writing validation records under app.{domain}, which is the half of the DNS
# carve-out that claiming the name does not exercise.
#
# Every resource created here is tagged evize:app=test so it can be found and
# deleted afterwards. Route 53 record sets are the exception — AWS only allows
# tags on hosted zones and health checks — so app.{domain} is cleaned up by name.

set -uo pipefail

REGION="${ENCLAVIZE_REGION:-us-east-1}"
COMMIT="${ENCLAVIZE_COMMIT:-unknown}"
DOMAIN="${ENCLAVIZE_DOMAIN:-}"
NAME=evize-app
DEPLOYED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RESULTS=/tmp/probe-results.tsv

log() { echo "[app] $*"; }
: > "$RESULTS"

# --- who and where are we -------------------------------------------------

TOKEN="$(curl -sX PUT http://169.254.169.254/latest/api/token \
          -H 'X-aws-ec2-metadata-token-ttl-seconds: 600')"
imds() { curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$1"; }
INSTANCE_ID="$(imds instance-id)"
VPC_ID="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
           --query 'Reservations[0].Instances[0].VpcId' --output text)"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

log "account=$ACCOUNT instance=$INSTANCE_ID vpc=$VPC_ID commit=$COMMIT"

TAGS="Key=evize:app,Value=test Key=evize:commit,Value=$COMMIT Key=evize:deployed-at,Value=$DEPLOYED_AT"
ELB_TAGS="Key=evize:app,Value=test Key=evize:commit,Value=$COMMIT"

# --- probe the boundary ---------------------------------------------------
#
# Real attempts, not policy simulation. A simulated answer models what IAM
# would decide; an attempt is what IAM did decide. The cost is that a broken
# fence is actually breached rather than merely reported — acceptable in a
# sacrificial account, where a silent hole is the worse outcome by far.

probe() {                       # probe <expectation> <label> <command...>
  local expect="$1" label="$2"; shift 2
  local output verdict
  if output="$("$@" 2>&1)"; then
    [ "$expect" = allow ] && verdict=ok || verdict=HOLE
  else
    [ "$expect" = deny ] && verdict=ok || verdict=BLOCKED
  fi
  printf '%s\t%s\t%s\t%s\n' "$verdict" "$expect" "$label" \
    "$(echo "$output" | tr '\n' ' ' | cut -c1-160)" >> "$RESULTS"
  log "$label -> $verdict"
}

ZONE_ID="$(aws route53 list-hosted-zones-by-name --dns-name "$DOMAIN" \
            --query 'HostedZones[0].Id' --output text 2>/dev/null | sed 's|/hostedzone/||')"

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

# Things the application legitimately needs.
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
  .why { opacity:.5; font-size:.8rem; font-family:ui-monospace, monospace; }
  dl { display:grid; grid-template-columns:auto 1fr; gap:.3rem 1rem; font-size:.85rem; opacity:.7; margin-top:2.5rem; }
  dt { font-weight:600; }
  dd { margin:0; font-family:ui-monospace, monospace; }
</style>
<main>
HEAD

  echo "<h1>permission boundary</h1>"
  echo "<p class=sub>probed from inside the sealed account, by the application itself</p>"

  if [ "$HOLES" -gt 0 ]; then
    echo "<div class='verdict fail'>$HOLES hole(s): the boundary permitted something it should refuse.</div>"
  elif [ "$BLOCKED" -gt 0 ]; then
    echo "<div class='verdict fail'>$BLOCKED over-restriction(s): the application was denied something it needs.</div>"
  else
    echo "<div class='verdict pass'>The boundary held. Everything forbidden was refused; everything needed was permitted.</div>"
  fi

  echo "<table><tr><th>probe</th><th>expected</th><th>result</th><th>what AWS said</th></tr>"
  while IFS=$'\t' read -r verdict expect label detail; do
    case "$verdict" in
      ok)      cls=ok;      word=$([ "$expect" = deny ] && echo "denied" || echo "allowed") ;;
      HOLE)    cls=hole;    word="ALLOWED — HOLE" ;;
      BLOCKED) cls=blocked; word="DENIED — too strict" ;;
    esac
    echo "<tr><td>$label</td><td>$expect</td><td class=$cls>$word</td><td class=why>$(echo "$detail" | sed 's/&/\&amp;/g; s/</\&lt;/g')</td></tr>"
  done < "$RESULTS"
  echo "</table>"

  cat <<FOOT
<dl>
  <dt>account</dt><dd>$ACCOUNT</dd>
  <dt>commit</dt><dd>$COMMIT</dd>
  <dt>instance</dt><dd>$INSTANCE_ID</dd>
  <dt>deployed</dt><dd>$DEPLOYED_AT</dd>
</dl>
</main>
FOOT
} > /usr/share/nginx/html/index.html

# The same probes as machine-readable data, in the shape enclavize's e2e suite
# reads. The page above is for a person; this is so a test can assert on the
# result instead of scraping HTML. python3 rather than hand-rolled quoting:
# `detail` is whatever AWS said, and that contains quotes and backslashes.
python3 - "$RESULTS" "$ACCOUNT" "$COMMIT" "$INSTANCE_ID" "$DEPLOYED_AT" <<'PY' \
  > /usr/share/nginx/html/results.json
import csv, json, sys

path, account, commit, instance, deployed_at = sys.argv[1:6]
with open(path, newline="") as handle:
    probes = [
        {"name": label, "expected": expect, "verdict": verdict, "detail": detail}
        for verdict, expect, label, detail in csv.reader(handle, delimiter="\t")
    ]

json.dump({
    "ok": all(p["verdict"] == "ok" for p in probes),
    "account": account,
    "commit": commit,
    "instance": instance,
    "deployedAt": deployed_at,
    "probes": probes,
}, sys.stdout, indent=2)
sys.stdout.write("\n")
PY

systemctl enable --now nginx >/dev/null 2>&1
log "nginx serving the results"

# --- put an ALB in front of it --------------------------------------------
#
# Reused across deploys rather than rebuilt, so app.{domain} keeps pointing at
# the same load balancer and only the registered target changes.

SUBNETS="$(aws ec2 describe-subnets --region "$REGION" \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=default-for-az,Values=true" \
  --query 'Subnets[].SubnetId' --output text)"

alb_sg="$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=$NAME-alb" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)"
if [ "$alb_sg" = "None" ] || [ -z "$alb_sg" ]; then
  alb_sg="$(aws ec2 create-security-group --region "$REGION" --group-name "$NAME-alb" \
    --description "evize-app load balancer" --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=evize:app,Value=test},{Key=Name,Value=$NAME-alb}]" \
    --query GroupId --output text)"
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$alb_sg" \
    --protocol tcp --port 80 --cidr 0.0.0.0/0 >/dev/null
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$alb_sg" \
    --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null
fi

app_sg="$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=$NAME-instance" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)"
if [ "$app_sg" = "None" ] || [ -z "$app_sg" ]; then
  app_sg="$(aws ec2 create-security-group --region "$REGION" --group-name "$NAME-instance" \
    --description "evize-app instance" --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=evize:app,Value=test},{Key=Name,Value=$NAME-instance}]" \
    --query GroupId --output text)"
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$app_sg" \
    --protocol tcp --port 80 --source-group "$alb_sg" >/dev/null
fi

# Attach alongside whatever the instance already has, rather than replacing it.
EXISTING="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' --output text)"
aws ec2 modify-instance-attribute --region "$REGION" --instance-id "$INSTANCE_ID" \
  --groups $EXISTING "$app_sg" >/dev/null 2>&1 || true

tg_arn="$(aws elbv2 describe-target-groups --region "$REGION" --names "$NAME" \
  --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null)"
if [ -z "$tg_arn" ] || [ "$tg_arn" = "None" ]; then
  tg_arn="$(aws elbv2 create-target-group --region "$REGION" --name "$NAME" \
    --protocol HTTP --port 80 --vpc-id "$VPC_ID" --target-type instance \
    --health-check-path / --tags $ELB_TAGS \
    --query 'TargetGroups[0].TargetGroupArn' --output text)"
fi

# This deploy's instance replaces the last one's, and the last one goes.
#
# enclavize launches one instance per apply and hands it over; what becomes of
# the previous one is the application's call, and nothing else will make it.
# Left alone they accumulate — one more running instance per commit applied,
# each still holding the security group this script wants to delete later.
#
# A real deployment would drain connections first. There is nothing here worth
# draining.
for old in $(aws elbv2 describe-target-health --region "$REGION" --target-group-arn "$tg_arn" \
              --query 'TargetHealthDescriptions[].Target.Id' --output text 2>/dev/null); do
  if [ "$old" != "$INSTANCE_ID" ]; then
    aws elbv2 deregister-targets --region "$REGION" \
      --target-group-arn "$tg_arn" --targets "Id=$old" >/dev/null 2>&1
    aws ec2 terminate-instances --region "$REGION" --instance-ids "$old" >/dev/null 2>&1 \
      && log "retired $old, which this deploy replaces"
  fi
done
aws elbv2 register-targets --region "$REGION" --target-group-arn "$tg_arn" \
  --targets "Id=$INSTANCE_ID" >/dev/null

alb_arn="$(aws elbv2 describe-load-balancers --region "$REGION" --names "$NAME" \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null)"
if [ -z "$alb_arn" ] || [ "$alb_arn" = "None" ]; then
  alb_arn="$(aws elbv2 create-load-balancer --region "$REGION" --name "$NAME" \
    --type application --scheme internet-facing --security-groups "$alb_sg" \
    --subnets $SUBNETS --tags $ELB_TAGS \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text)"
  aws elbv2 create-listener --region "$REGION" --load-balancer-arn "$alb_arn" \
    --protocol HTTP --port 80 --tags $ELB_TAGS \
    --default-actions '[{"Type":"redirect","RedirectConfig":{"Protocol":"HTTPS","Port":"443","StatusCode":"HTTP_301"}}]' >/dev/null
  log "waiting for the load balancer"
  aws elbv2 wait load-balancer-available --region "$REGION" --load-balancer-arns "$alb_arn"
fi

# --- a certificate of the application's own --------------------------------
#
# enclavize's certificate covers dashboard., proof. and apply. — its own names,
# not this one. So the application asks for its own, and validates it by writing
# records under app.{domain}: another use of the same carve-out that lets it
# claim the name at all, and the part of that permission the A record alone
# never exercises.
#
# Reused once issued. Requesting per deploy would leave a trail of certificates
# and pay the validation wait every time.

cert_arn="$(aws acm list-certificates --region "$REGION" \
  --query "CertificateSummaryList[?DomainName=='app.$DOMAIN'].CertificateArn|[0]" --output text 2>/dev/null)"
if [ -z "$cert_arn" ] || [ "$cert_arn" = "None" ]; then
  cert_arn="$(aws acm request-certificate --region "$REGION" --domain-name "app.$DOMAIN" \
    --validation-method DNS --tags Key=evize:app,Value=test \
    --query CertificateArn --output text)"
  log "requested a certificate for app.$DOMAIN"
fi

# The validation record only appears once ACM has worked out what it wants.
for _ in $(seq 1 30); do
  read -r rr_name rr_type rr_value <<< "$(aws acm describe-certificate --region "$REGION" \
    --certificate-arn "$cert_arn" \
    --query 'Certificate.DomainValidationOptions[0].ResourceRecord.[Name,Type,Value]' \
    --output text 2>/dev/null)"
  [ -n "$rr_name" ] && [ "$rr_name" != "None" ] && break
  sleep 5
done

if [ -n "$ZONE_ID" ] && [ "$ZONE_ID" != "None" ] && [ "$rr_name" != "None" ]; then
  aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" --change-batch "{
    \"Comment\": \"evize-app certificate validation\",
    \"Changes\": [{\"Action\": \"UPSERT\", \"ResourceRecordSet\": {
      \"Name\": \"$rr_name\", \"Type\": \"$rr_type\", \"TTL\": 300,
      \"ResourceRecords\": [{\"Value\": \"$rr_value\"}]}}]
  }" >/dev/null && log "published the validation record for app.$DOMAIN"
fi

log "waiting for the certificate"
aws acm wait certificate-validated --region "$REGION" --certificate-arn "$cert_arn" 2>/dev/null \
  || log "certificate not validated yet; the HTTPS listener may not come up this deploy"

if ! aws elbv2 describe-listeners --region "$REGION" --load-balancer-arn "$alb_arn" \
     --query 'Listeners[?Port==`443`]' --output text 2>/dev/null | grep -q .; then
  aws elbv2 create-listener --region "$REGION" --load-balancer-arn "$alb_arn" \
    --protocol HTTPS --port 443 --certificates "CertificateArn=$cert_arn" \
    --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 --tags $ELB_TAGS \
    --default-actions "Type=forward,TargetGroupArn=$tg_arn" >/dev/null \
    && log "listening on 443"
fi

read -r ALB_DNS ALB_ZONE <<< "$(aws elbv2 describe-load-balancers --region "$REGION" \
  --load-balancer-arns "$alb_arn" --query 'LoadBalancers[0].[DNSName,CanonicalHostedZoneId]' --output text)"

# --- claim app.{domain} ---------------------------------------------------
#
# The boundary protects dashboard., proof., and the apex MX/NS/SOA, and leaves
# the rest of the zone to the application. This is that carve-out being used.

if [ -n "$ZONE_ID" ] && [ "$ZONE_ID" != "None" ]; then
  aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" --change-batch "{
    \"Comment\": \"evize-app\",
    \"Changes\": [{\"Action\": \"UPSERT\", \"ResourceRecordSet\": {
      \"Name\": \"app.$DOMAIN\", \"Type\": \"A\",
      \"AliasTarget\": {\"HostedZoneId\": \"$ALB_ZONE\", \"DNSName\": \"$ALB_DNS\", \"EvaluateTargetHealth\": false}}}]
  }" >/dev/null && log "app.$DOMAIN -> $ALB_DNS"
fi

log "done — https://app.$DOMAIN (or http://$ALB_DNS)"
log "holes=$HOLES over-restrictions=$BLOCKED"
