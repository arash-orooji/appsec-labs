#!/usr/bin/env bash
# AWS WAF Classic WebACL for DNS rebinding lab.
# LocalStack Community returns 501 for wafv2 and waf-regional.
set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="$REGION"
export AWS_PAGER=""

WEB_ACL_NAME="DNS-Rebinding-Protection"
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
    "http://127.0.0.1:4585"
    "http://localhost:4585"
    "http://waf-classic:4585"
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
  echo "       Start the waf-classic sidecar on :4585 and re-run."
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

echo "==> ByteMatchSet Host CONTAINS rebind.lab"
REBIND_ID="$(aws_waf create-byte-match-set --name Rebind-Lab-Name --change-token "$(token)" --query 'ByteMatchSet.ByteMatchSetId' --output text)"
aws_waf update-byte-match-set \
  --byte-match-set-id "$REBIND_ID" \
  --change-token "$(token)" \
  --updates 'Action=INSERT,ByteMatchTuple={FieldToMatch={Type=HEADER,Data=host},TargetString=rebind.lab,TextTransformation=LOWERCASE,PositionalConstraint=CONTAINS}' >/dev/null

echo "==> ByteMatchSet Host CONTAINS target.local"
LOCAL_ID="$(aws_waf create-byte-match-set --name Internal-Local-Name --change-token "$(token)" --query 'ByteMatchSet.ByteMatchSetId' --output text)"
aws_waf update-byte-match-set \
  --byte-match-set-id "$LOCAL_ID" \
  --change-token "$(token)" \
  --updates 'Action=INSERT,ByteMatchTuple={FieldToMatch={Type=HEADER,Data=host},TargetString=target.local,TextTransformation=LOWERCASE,PositionalConstraint=CONTAINS}' >/dev/null

echo "==> ByteMatchSet Host CONTAINS 0.0.0.0"
ZERO_ID="$(aws_waf create-byte-match-set --name Unspecified-Address --change-token "$(token)" --query 'ByteMatchSet.ByteMatchSetId' --output text)"
aws_waf update-byte-match-set \
  --byte-match-set-id "$ZERO_ID" \
  --change-token "$(token)" \
  --updates 'Action=INSERT,ByteMatchTuple={FieldToMatch={Type=HEADER,Data=host},TargetString=0.0.0.0,TextTransformation=LOWERCASE,PositionalConstraint=CONTAINS}' >/dev/null

echo "==> Rule Block-Rebind-Lab-Name"
R1="$(aws_waf create-rule --name Block-Rebind-Lab-Name --metric-name BlockRebindLabName --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule \
  --rule-id "$R1" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$REBIND_ID}" >/dev/null

echo "==> Rule Block-Internal-Local-Name"
R2="$(aws_waf create-rule --name Block-Internal-Local-Name --metric-name BlockInternalLocalName --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule \
  --rule-id "$R2" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$LOCAL_ID}" >/dev/null

echo "==> Rule Block-Unspecified-Address"
R3="$(aws_waf create-rule --name Block-Unspecified-Address --metric-name BlockUnspecifiedAddress --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule \
  --rule-id "$R3" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$ZERO_ID}" >/dev/null

echo "==> WebACL $WEB_ACL_NAME"
WEB_ACL_ID="$(aws_waf create-web-acl \
  --name "$WEB_ACL_NAME" \
  --metric-name DnsRebindingACL \
  --default-action Type=ALLOW \
  --change-token "$(token)" \
  --query WebACL.WebACLId \
  --output text)"

aws_waf update-web-acl \
  --web-acl-id "$WEB_ACL_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=1,RuleId=$R1,Action={Type=BLOCK},Type=REGULAR}" >/dev/null

aws_waf update-web-acl \
  --web-acl-id "$WEB_ACL_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=2,RuleId=$R2,Action={Type=BLOCK},Type=REGULAR}" >/dev/null

aws_waf update-web-acl \
  --web-acl-id "$WEB_ACL_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=3,RuleId=$R3,Action={Type=BLOCK},Type=REGULAR}" >/dev/null

echo "==> WebACL created: $WEB_ACL_ID"
aws_waf list-web-acls
echo "Live enforcement is waf-proxy on :8980 (Host pin + these signatures)."
echo "WAFv2 is not available on LocalStack Community."
