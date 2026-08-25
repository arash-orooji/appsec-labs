#!/usr/bin/env bash
# Create AWS WAF Classic (waf-regional) resources for request smuggling.
# LocalStack Community 3.x returns 501 for BOTH wafv2 and waf-regional.
set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="$REGION"
export AWS_PAGER=""

WEB_ACL_NAME="Request-Smuggling-Protection"

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
    "http://127.0.0.1:4569"
    "http://localhost:4569"
    "http://waf-classic:4568"
    "http://127.0.0.1:4568"
    "http://localhost:4568"
    "http://localhost:4567"
    "http://127.0.0.1:4567"
    "http://localhost:4566"
    "http://127.0.0.1:4566"
  )

  local seen=""
  local ep api
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
echo "    region=$REGION"

if ! pick_endpoint_and_api; then
  echo "ERROR: No AWS WAF Classic API found."
  echo "       LocalStack Community does not implement wafv2 or waf-regional (Pro-only)."
  echo "       Start the waf-classic sidecar (port 4569) and re-run this script."
  if [[ "$IN_LOCALSTACK_INIT" -eq 1 ]]; then
    echo "WARN: continuing LocalStack boot; run setup-waf.sh from the host once waf-classic is up."
    exit 0
  fi
  exit 1
fi

echo "    endpoint=$ENDPOINT api=$WAF_API (AWS WAF Classic — not WAFv2)"

EXISTING_ID="$(aws_waf list-web-acls --query "WebACLs[?Name=='$WEB_ACL_NAME'].WebACLId" --output text 2>/dev/null || true)"
if [[ -n "${EXISTING_ID:-}" && "$EXISTING_ID" != "None" ]]; then
  echo "==> WebACL already exists: $EXISTING_ID"
  aws_waf list-web-acls
  exit 0
fi

insert_byte_match() {
  local set_id="$1"
  local header="$2"
  local target="$3"
  local transform="${4:-LOWERCASE}"
  local pos="${5:-CONTAINS}"
  local tok jsonfile
  tok="$(token)"
  jsonfile="$(mktemp)"
  python3 - "$set_id" "$header" "$target" "$transform" "$pos" "$tok" "$jsonfile" <<'PY'
import json, sys
set_id, header, target, transform, pos, tok, path = sys.argv[1:]
with open(path, "w", encoding="utf-8") as fh:
    json.dump({
        "ByteMatchSetId": set_id,
        "ChangeToken": tok,
        "Updates": [{
            "Action": "INSERT",
            "ByteMatchTuple": {
                "FieldToMatch": {"Type": "HEADER", "Data": header},
                "TargetString": target,
                "TextTransformation": transform,
                "PositionalConstraint": pos,
            },
        }],
    }, fh)
PY
  aws_waf update-byte-match-set --cli-input-json "file://${jsonfile}" >/dev/null
  rm -f "$jsonfile"
}

echo "==> SizeConstraintSet Content-Length present (GE 0)"
CL_SIZE_ID="$(aws_waf create-size-constraint-set --name Content-Length-Present --change-token "$(token)" --query 'SizeConstraintSet.SizeConstraintSetId' --output text)"
aws_waf update-size-constraint-set \
  --size-constraint-set-id "$CL_SIZE_ID" \
  --change-token "$(token)" \
  --updates 'Action=INSERT,SizeConstraint={FieldToMatch={Type=HEADER,Data=content-length},TextTransformation=NONE,ComparisonOperator=GE,Size=0}' >/dev/null

echo "==> ByteMatchSet Transfer-Encoding CONTAINS chunked"
TE_CHUNKED_ID="$(aws_waf create-byte-match-set --name TE-Chunked --change-token "$(token)" --query 'ByteMatchSet.ByteMatchSetId' --output text)"
insert_byte_match "$TE_CHUNKED_ID" "transfer-encoding" "chunked"

echo "==> ByteMatchSet TE obfuscation (identity / comma / xchunked)"
TE_OBF_ID="$(aws_waf create-byte-match-set --name TE-Obfuscation --change-token "$(token)" --query 'ByteMatchSet.ByteMatchSetId' --output text)"
insert_byte_match "$TE_OBF_ID" "transfer-encoding" "identity"
insert_byte_match "$TE_OBF_ID" "transfer-encoding" "chunked,"
insert_byte_match "$TE_OBF_ID" "transfer-encoding" ",chunked"
insert_byte_match "$TE_OBF_ID" "transfer-encoding" "xchunked"

echo "==> ByteMatchSet malformed Content-Length (comma)"
CL_BAD_ID="$(aws_waf create-byte-match-set --name Malformed-Content-Length --change-token "$(token)" --query 'ByteMatchSet.ByteMatchSetId' --output text)"
insert_byte_match "$CL_BAD_ID" "content-length" "," "NONE"


echo "==> Rule Block-CL-TE-Smuggling (CL present AND TE chunked)"
CLTE_RULE_ID="$(aws_waf create-rule --name Block-CL-TE-Smuggling --metric-name BlockCLTESmuggling --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule \
  --rule-id "$CLTE_RULE_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=SizeConstraint,DataId=$CL_SIZE_ID}" >/dev/null
aws_waf update-rule \
  --rule-id "$CLTE_RULE_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$TE_CHUNKED_ID}" >/dev/null

echo "==> Rule Block-TE-Obfuscation"
TE_RULE_ID="$(aws_waf create-rule --name Block-TE-Obfuscation --metric-name BlockTEObfuscation --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule \
  --rule-id "$TE_RULE_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$TE_OBF_ID}" >/dev/null

echo "==> Rule Block-Malformed-Content-Length"
CL_RULE_ID="$(aws_waf create-rule --name Block-Malformed-Content-Length --metric-name BlockMalformedContentLength --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule \
  --rule-id "$CL_RULE_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$CL_BAD_ID}" >/dev/null

echo "==> WebACL $WEB_ACL_NAME default ALLOW"
WEB_ACL_ID="$(aws_waf create-web-acl \
  --name "$WEB_ACL_NAME" \
  --metric-name RequestSmugglingWebACL \
  --default-action Type=ALLOW \
  --change-token "$(token)" \
  --query WebACL.WebACLId \
  --output text)"

aws_waf update-web-acl \
  --web-acl-id "$WEB_ACL_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=1,RuleId=$CLTE_RULE_ID,Action={Type=BLOCK},Type=REGULAR}" >/dev/null

aws_waf update-web-acl \
  --web-acl-id "$WEB_ACL_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=2,RuleId=$TE_RULE_ID,Action={Type=BLOCK},Type=REGULAR}" >/dev/null

aws_waf update-web-acl \
  --web-acl-id "$WEB_ACL_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=3,RuleId=$CL_RULE_ID,Action={Type=BLOCK},Type=REGULAR}" >/dev/null

echo "==> WebACL created: $WEB_ACL_ID"
echo "==> Listing WebACLs:"
aws_waf list-web-acls

echo ""
echo "In production, associate this WebACL with an ALB or CloudFront distribution."
echo "In this lab, traffic on :8180 is enforced by waf-proxy using the same logic."
echo "API used: $WAF_API at $ENDPOINT (AWS WAF Classic). WAFv2 is not available on LocalStack Community."
