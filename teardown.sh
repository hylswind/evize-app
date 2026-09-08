#!/bin/bash
#
# Remove everything setup.sh created, so the account can be sealed again.
#
# enclavize's own teardown removes what enclavize built — the front door, and
# every instance it launched; only the application knows what the application
# built, which is why this lives here. It is run by tests/e2e/unseal.py after
# the instances and before the rest.
#
# Called with ENCLAVIZE_DOMAIN set, and credentials that can act in the
# account. Safe to run twice: everything here tolerates its target already
# being gone.

set -uo pipefail

# The same environment setup.sh gets: the domain, and nothing else.
DOMAIN="${ENCLAVIZE_DOMAIN:-}"
REGION=us-east-1
export AWS_DEFAULT_REGION="$REGION"   # for the calls below that take no --region
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

log() { echo "[teardown] $*"; }

log "account=$ACCOUNT region=$REGION domain=${DOMAIN:-<unset>}"

# --- instances ------------------------------------------------------------
#
# enclavize retires each version as the next one is switched in, and its own
# teardown terminates whatever it launched. This catches anything still
# carrying the app's tag regardless — a version that never became healthy,
# say — and waits, because nothing behind it can go while it holds a group.

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
