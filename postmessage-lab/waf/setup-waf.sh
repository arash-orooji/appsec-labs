#!/usr/bin/env bash
set -euo pipefail
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="$REGION"
export AWS_PAGER=""

WEB_ACL_NAME="PostMessage-Protection"
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
aws_waf() { aws_base "$ENDPOINT" "$WAF_API" "$@"; }
token() { aws_waf get-change-token --query ChangeToken --output text; }
probe_endpoint() {
  AWS_MAX_ATTEMPTS=1 aws_base "$1" "$2" get-change-token --query ChangeToken --output text >/dev/null 2>&1
}

pick_endpoint_and_api() {
  local candidates=()
  if [[ -n "${AWS_ENDPOINT_URL:-}" ]]; then candidates+=("$AWS_ENDPOINT_URL"); fi
  candidates+=("http://127.0.0.1:4583" "http://localhost:4583" "http://waf-classic:4583")
  local seen="" ep api
  for ep in "${candidates[@]}"; do
    case " $seen " in *" $ep "*) continue ;; esac
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
  echo "ERROR: No AWS WAF Classic API on :4583"
  if [[ "$IN_LOCALSTACK_INIT" -eq 1 ]]; then exit 0; fi
  exit 1
fi
echo "    endpoint=$ENDPOINT api=$WAF_API"

EXISTING_ID="$(aws_waf list-web-acls --query "WebACLs[?Name=='$WEB_ACL_NAME'].WebACLId" --output text 2>/dev/null || true)"
if [[ -n "${EXISTING_ID:-}" && "$EXISTING_ID" != "None" ]]; then
  echo "==> WebACL already exists: $EXISTING_ID"
  aws_waf list-web-acls
  exit 0
fi

make_byte() {
  local name="$1" target="$2"
  local id
  id="$(aws_waf create-byte-match-set --name "$name" --change-token "$(token)" --query 'ByteMatchSet.ByteMatchSetId' --output text)"
  aws_waf update-byte-match-set \
    --byte-match-set-id "$id" \
    --change-token "$(token)" \
    --updates "Action=INSERT,ByteMatchTuple={FieldToMatch={Type=BODY},TargetString=${target},TextTransformation=NONE,PositionalConstraint=CONTAINS}" >/dev/null
  echo "$id"
}

B1="$(make_byte PM-banner banner)"
B2="$(make_byte PM-proto __proto__)"
B3="$(make_byte PM-null harbor-link)"

R1="$(aws_waf create-rule --name Block-Unpinned-PostMessage-Origin --metric-name BlockUnpinnedPm --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule --rule-id "$R1" --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$B1}" >/dev/null

R2="$(aws_waf create-rule --name Block-PostMessage-Prototype-Merge --metric-name BlockPmProto --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule --rule-id "$R2" --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$B2}" >/dev/null

R3="$(aws_waf create-rule --name Block-Null-Origin-Message --metric-name BlockNullPm --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule --rule-id "$R3" --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$B3}" >/dev/null

WEB_ACL_ID="$(aws_waf create-web-acl --name "$WEB_ACL_NAME" --metric-name PostMessageACL \
  --default-action Type=ALLOW --change-token "$(token)" --query WebACL.WebACLId --output text)"
aws_waf update-web-acl --web-acl-id "$WEB_ACL_ID" --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=1,RuleId=$R1,Action={Type=BLOCK},Type=REGULAR}" >/dev/null
aws_waf update-web-acl --web-acl-id "$WEB_ACL_ID" --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=2,RuleId=$R2,Action={Type=BLOCK},Type=REGULAR}" >/dev/null
aws_waf update-web-acl --web-acl-id "$WEB_ACL_ID" --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=3,RuleId=$R3,Action={Type=BLOCK},Type=REGULAR}" >/dev/null

echo "==> WebACL created: $WEB_ACL_ID"
aws_waf list-web-acls
echo "Enforced on :8880 by waf-proxy."
