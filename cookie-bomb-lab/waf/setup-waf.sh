#!/usr/bin/env bash
# AWS WAF Classic WebACL for the Cookie Bomb lab.
# LocalStack Community returns 501 for wafv2 and waf-regional.
set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="$REGION"
export AWS_PAGER=""

WEB_ACL_NAME="Cookie-Bomb-Protection"
WAF_API="waf-regional"
ENDPOINT="${AWS_ENDPOINT_URL:-}"

IN_LOCALSTACK_INIT=0
if [[ -f /etc/localstack/init/ready.d/01-setup-waf.sh ]]; then
  IN_LOCALSTACK_INIT=1
fi

aws_base() {
  local ep="$1"
  shift
  aws --endpoint-url="$ep" --region="$REGION" "$@"
}

aws_waf() {
  aws_base "$ENDPOINT" "$WAF_API" "$@"
}

token() {
  aws_waf get-change-token --query ChangeToken --output text
}

probe_endpoint() {
  local ep="$1"
  local api="$2"
  AWS_MAX_ATTEMPTS=1 aws_base "$ep" "$api" get-change-token --query ChangeToken --output text >/dev/null 2>&1
}

pick_endpoint_and_api() {
  local candidates=()
  if [[ -n "${AWS_ENDPOINT_URL:-}" ]]; then
    candidates+=("$AWS_ENDPOINT_URL")
  fi
  candidates+=(
    "http://127.0.0.1:4571"
    "http://localhost:4571"
    "http://waf-classic:4571"
    "http://127.0.0.1:4568"
    "http://localhost:4568"
    "http://localhost:4570"
    "http://127.0.0.1:4570"
  )
  local seen="" ep api
  for ep in "${candidates[@]}"; do
    case " $seen " in
      *" $ep "*) continue ;;
    esac
    seen+=" $ep"
    for api in waf-regional waf; do
      if probe_endpoint "$ep" "$api"; then
        ENDPOINT="$ep"
        WAF_API="$api"
        return 0
      fi
    done
  done
  return 1
}

echo "==> Creating WAF Classic WebACL: $WEB_ACL_NAME"
if ! pick_endpoint_and_api; then
  echo "ERROR: No AWS WAF Classic API found (LocalStack Community is Pro-only for WAF)."
  echo "       Start the waf-classic sidecar on :4571 and re-run."
  if [[ "$IN_LOCALSTACK_INIT" -eq 1 ]]; then
    exit 0
  fi
  exit 1
fi
echo "    endpoint=$ENDPOINT api=$WAF_API"

EXISTING_ID="$(aws_waf list-web-acls --query "WebACLs[?Name=='$WEB_ACL_NAME'].WebACLId" --output text 2>/dev/null || true)"
if [[ -n "${EXISTING_ID:-}" && "$EXISTING_ID" != "None" ]]; then
  echo "==> WebACL already exists: $EXISTING_ID"
  aws_waf list-web-acls
  exit 0
fi

echo "==> SizeConstraintSet QUERY_STRING GE 1024"
QS_ID="$(aws_waf create-size-constraint-set --name Oversized-Query-String --change-token "$(token)" --query 'SizeConstraintSet.SizeConstraintSetId' --output text)"
aws_waf update-size-constraint-set \
  --size-constraint-set-id "$QS_ID" \
  --change-token "$(token)" \
  --updates 'Action=INSERT,SizeConstraint={FieldToMatch={Type=QUERY_STRING},TextTransformation=NONE,ComparisonOperator=GE,Size=1024}' >/dev/null

echo "==> SizeConstraintSet Cookie header GE 4096"
CK_ID="$(aws_waf create-size-constraint-set --name Oversized-Cookie-Header --change-token "$(token)" --query 'SizeConstraintSet.SizeConstraintSetId' --output text)"
aws_waf update-size-constraint-set \
  --size-constraint-set-id "$CK_ID" \
  --change-token "$(token)" \
  --updates 'Action=INSERT,SizeConstraint={FieldToMatch={Type=HEADER,Data=cookie},TextTransformation=NONE,ComparisonOperator=GE,Size=4096}' >/dev/null

echo "==> Rule Block-Oversized-Query"
QS_RULE="$(aws_waf create-rule --name Block-Oversized-Query --metric-name BlockOversizedQuery --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule \
  --rule-id "$QS_RULE" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=SizeConstraint,DataId=$QS_ID}" >/dev/null

echo "==> Rule Block-Oversized-Cookie"
CK_RULE="$(aws_waf create-rule --name Block-Oversized-Cookie --metric-name BlockOversizedCookie --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule \
  --rule-id "$CK_RULE" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=SizeConstraint,DataId=$CK_ID}" >/dev/null

echo "==> WebACL $WEB_ACL_NAME"
WEB_ACL_ID="$(aws_waf create-web-acl \
  --name "$WEB_ACL_NAME" \
  --metric-name CookieBombWebACL \
  --default-action Type=ALLOW \
  --change-token "$(token)" \
  --query WebACL.WebACLId \
  --output text)"

aws_waf update-web-acl \
  --web-acl-id "$WEB_ACL_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=1,RuleId=$QS_RULE,Action={Type=BLOCK},Type=REGULAR}" >/dev/null

aws_waf update-web-acl \
  --web-acl-id "$WEB_ACL_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=2,RuleId=$CK_RULE,Action={Type=BLOCK},Type=REGULAR}" >/dev/null

echo "==> WebACL created: $WEB_ACL_ID"
aws_waf list-web-acls
echo "In this lab, :8280 is enforced by waf-proxy. WAFv2 is not available on LocalStack Community."
