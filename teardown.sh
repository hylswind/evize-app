#!/bin/bash
#
# Remove everything setup.sh created, so the account can be sealed again.
#
# enclavize's own teardown removes what enclavize built; only the application
# knows what the application built, which is why this lives here. It is run by
# tests/e2e/unseal.py before the hosted zone goes, because app.{domain} has to
# be deleted while there is still a zone to delete it from.
#
# Called with ENCLAVIZE_REGION and ENCLAVIZE_DOMAIN set, and credentials that
# can act in the account. Safe to run twice: everything here tolerates its
# target already being gone.

set -uo pipefail

REGION="${ENCLAVIZE_REGION:-us-east-1}"
DOMAIN="${ENCLAVIZE_DOMAIN:-}"
NAME=evize-app
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

log() { echo "[teardown] $*"; }
gone() { [ -z "$1" ] || [ "$1" = "None" ]; }

log "account=$ACCOUNT region=$REGION domain=${DOMAIN:-<unset>}"

# --- app.{domain} ---------------------------------------------------------
#
# By name, not by tag: Route 53 only allows tags on hosted zones and health
# checks, never on record sets.

if [ -n "$DOMAIN" ]; then
  ZONE_ID="$(aws route53 list-hosted-zones-by-name --dns-name "$DOMAIN" \
    --query 'HostedZones[0].Id' --output text 2>/dev/null | sed 's|/hostedzone/||')"
  if ! gone "$ZONE_ID"; then
    RECORD="$(aws route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" \
      --query "ResourceRecordSets[?Name=='app.$DOMAIN.']|[0]" --output json 2>/dev/null)"
    if [ -n "$RECORD" ] && [ "$RECORD" != "null" ]; then
      aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" \
        --change-batch "{\"Changes\":[{\"Action\":\"DELETE\",\"ResourceRecordSet\":$RECORD}]}" \
        >/dev/null 2>&1 && log "deleted app.$DOMAIN" || log "could not delete app.$DOMAIN"
    else
      log "no app.$DOMAIN record"
    fi
  fi
fi

# --- the load balancer ----------------------------------------------------
#
# Listeners, then the balancer, then a wait. The security groups below cannot
# go while anything still references them, and deletion is not instant.

ALB_ARN="$(aws elbv2 describe-load-balancers --region "$REGION" --names "$NAME" \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null)"
if gone "$ALB_ARN"; then
  log "no load balancer"
else
  for listener in $(aws elbv2 describe-listeners --region "$REGION" \
      --load-balancer-arn "$ALB_ARN" --query 'Listeners[].ListenerArn' --output text 2>/dev/null); do
    aws elbv2 delete-listener --region "$REGION" --listener-arn "$listener" >/dev/null 2>&1
  done
  aws elbv2 delete-load-balancer --region "$REGION" --load-balancer-arn "$ALB_ARN" >/dev/null 2>&1
  log "deleting the load balancer; waiting for it to go"
  aws elbv2 wait load-balancers-deleted --region "$REGION" --load-balancer-arns "$ALB_ARN" 2>/dev/null
  log "load balancer gone"
fi

TG_ARN="$(aws elbv2 describe-target-groups --region "$REGION" --names "$NAME" \
  --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null)"
if gone "$TG_ARN"; then
  log "no target group"
else
  aws elbv2 delete-target-group --region "$REGION" --target-group-arn "$TG_ARN" >/dev/null 2>&1 \
    && log "deleted target group $NAME" || log "could not delete target group"
fi

# --- instances ------------------------------------------------------------
#
# Before the security groups: one is attached to every instance this app
# deployed, and an attached group cannot be deleted.

INSTANCES="$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:evize:app,Values=test" \
            "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null)"
if [ -n "$INSTANCES" ]; then
  aws ec2 terminate-instances --region "$REGION" --instance-ids $INSTANCES >/dev/null 2>&1
  log "terminating $INSTANCES; waiting"
  aws ec2 wait instance-terminated --region "$REGION" --instance-ids $INSTANCES 2>/dev/null
  log "instances terminated"
else
  log "no tagged instances"
fi

# --- security groups ------------------------------------------------------
#
# Last, and retried: a group stays undeletable for a while after the things
# referencing it are gone, and the instance group is referenced by the ALB
# group's rules.

for group_name in "$NAME-instance" "$NAME-alb"; do
  gid="$(aws ec2 describe-security-groups --region "$REGION" \
    --filters "Name=group-name,Values=$group_name" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)"
  if gone "$gid"; then
    log "no security group $group_name"
    continue
  fi
  for attempt in 1 2 3 4 5 6; do
    if aws ec2 delete-security-group --region "$REGION" --group-id "$gid" >/dev/null 2>&1; then
      log "deleted security group $group_name"
      break
    fi
    [ "$attempt" = 6 ] && log "could not delete security group $group_name ($gid); still in use"
    sleep 10
  done
done

# --- the bucket -----------------------------------------------------------

BUCKET="evize-app-$ACCOUNT"
if aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  aws s3 rm "s3://$BUCKET" --recursive >/dev/null 2>&1
  aws s3api delete-bucket --bucket "$BUCKET" >/dev/null 2>&1 \
    && log "deleted bucket $BUCKET" || log "could not delete bucket $BUCKET"
else
  log "no bucket $BUCKET"
fi

# --- anything else still carrying the tag ---------------------------------
#
# Reported rather than deleted. A resource here means setup.sh grew something
# this script does not know about yet.

LEFT="$(aws resourcegroupstaggingapi get-resources --region "$REGION" \
  --tag-filters "Key=evize:app,Values=test" \
  --query 'ResourceTagMappingList[].ResourceARN' --output text 2>/dev/null)"
if [ -n "$LEFT" ]; then
  log "still tagged evize:app=test:"
  for arn in $LEFT; do log "  $arn"; done
else
  log "nothing left tagged evize:app=test"
fi

log "done"
