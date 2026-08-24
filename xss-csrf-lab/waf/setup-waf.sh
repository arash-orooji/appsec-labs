#!/usr/bin/env bash
# Create AWS WAF Classic (waf-regional) resources on LocalStack Community.
# LocalStack Community does not support WAFv2 — do not call `aws wafv2` here.
set -euo pipefail

ENDPOINT="${AWS_ENDPOINT_URL:-http://localhost:4566}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="$REGION"
export AWS_PAGER=""

WEB_ACL_NAME="XSS-CSRF-Protection"
XSS_SET_NAME="XSS-Query-Uri-Body"
ORIGIN_SET_NAME="Legitimate-Origin"
METHOD_SET_NAME="HTTP-POST-Method"
URI_SET_NAME="Update-Email-URI"

WAF_API="waf-regional"

aws_base() {
  aws --endpoint-url="$ENDPOINT" --region="$REGION" --no-cli-pager "$@"
}

aws_waf() {
  aws_base "$WAF_API" "$@"
}

token() {
  aws_waf get-change-token --query ChangeToken --output text
}

pick_waf_api() {
  if aws_base waf-regional get-change-token >/dev/null 2>&1; then
    WAF_API="waf-regional"
    return
  fi
  if aws_base waf get-change-token >/dev/null 2>&1; then
    WAF_API="waf"
    return
  fi
  echo "ERROR: LocalStack Community did not accept WAF Classic APIs (waf-regional / waf)." >&2
  echo "       WAFv2 is Pro-only. This lab requires classic WAF." >&2
  return 1
}

echo "==> Creating WAF Classic WebACL: $WEB_ACL_NAME"
echo "    endpoint=$ENDPOINT region=$REGION"

pick_waf_api
echo "    api=$WAF_API (AWS WAF Classic — not WAFv2)"

EXISTING_ID="$(aws_waf list-web-acls --query "WebACLs[?Name=='$WEB_ACL_NAME'].WebACLId" --output text 2>/dev/null || true)"
if [[ -n "${EXISTING_ID:-}" && "$EXISTING_ID" != "None" ]]; then
  echo "==> WebACL already exists: $EXISTING_ID"
  aws_waf list-web-acls
  exit 0
fi

echo "==> XssMatchSet ($XSS_SET_NAME) inspecting QUERY_STRING, URI, BODY"
XSS_SET_ID="$(aws_waf create-xss-match-set --name "$XSS_SET_NAME" --change-token "$(token)" --query 'XssMatchSet.XssMatchSetId' --output text)"
for FIELD in QUERY_STRING URI BODY; do
  aws_waf update-xss-match-set \
    --xss-match-set-id "$XSS_SET_ID" \
    --change-token "$(token)" \
    --updates "Action=INSERT,XssMatchTuple={FieldToMatch={Type=$FIELD},TextTransformation=URL_DECODE}"
done

echo "==> ByteMatchSet ($METHOD_SET_NAME) METHOD EXACTLY POST"
METHOD_SET_ID="$(aws_waf create-byte-match-set --name "$METHOD_SET_NAME" --change-token "$(token)" --query 'ByteMatchSet.ByteMatchSetId' --output text)"
aws_waf update-byte-match-set \
  --byte-match-set-id "$METHOD_SET_ID" \
  --change-token "$(token)" \
  --updates 'Action=INSERT,ByteMatchTuple={FieldToMatch={Type=METHOD},TargetString=POST,TextTransformation=NONE,PositionalConstraint=EXACTLY}'

echo "==> ByteMatchSet ($URI_SET_NAME) URI CONTAINS /update-email"
URI_SET_ID="$(aws_waf create-byte-match-set --name "$URI_SET_NAME" --change-token "$(token)" --query 'ByteMatchSet.ByteMatchSetId' --output text)"
aws_waf update-byte-match-set \
  --byte-match-set-id "$URI_SET_ID" \
  --change-token "$(token)" \
  --updates 'Action=INSERT,ByteMatchTuple={FieldToMatch={Type=URI},TargetString=/update-email,TextTransformation=LOWERCASE,PositionalConstraint=CONTAINS}'

echo "==> ByteMatchSet ($ORIGIN_SET_NAME) Origin STARTS_WITH http://localhost:3000"
ORIGIN_SET_ID="$(aws_waf create-byte-match-set --name "$ORIGIN_SET_NAME" --change-token "$(token)" --query 'ByteMatchSet.ByteMatchSetId' --output text)"
aws_waf update-byte-match-set \
  --byte-match-set-id "$ORIGIN_SET_ID" \
  --change-token "$(token)" \
  --updates 'Action=INSERT,ByteMatchTuple={FieldToMatch={Type=HEADER,Data=origin},TargetString=http://localhost:3000,TextTransformation=LOWERCASE,PositionalConstraint=STARTS_WITH}'
aws_waf update-byte-match-set \
  --byte-match-set-id "$ORIGIN_SET_ID" \
  --change-token "$(token)" \
  --updates 'Action=INSERT,ByteMatchTuple={FieldToMatch={Type=HEADER,Data=origin},TargetString=http://localhost:8080,TextTransformation=LOWERCASE,PositionalConstraint=STARTS_WITH}'

echo "==> Rule Block-XSS-Rule"
XSS_RULE_ID="$(aws_waf create-rule --name Block-XSS-Rule --metric-name BlockXSSRule --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule \
  --rule-id "$XSS_RULE_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=XssMatch,DataId=$XSS_SET_ID}"

echo "==> Rule Block-CSRF-Rule (POST /update-email AND NOT legitimate Origin)"
CSRF_RULE_ID="$(aws_waf create-rule --name Block-CSRF-Rule --metric-name BlockCSRFRule --change-token "$(token)" --query Rule.RuleId --output text)"
aws_waf update-rule \
  --rule-id "$CSRF_RULE_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$METHOD_SET_ID}"
aws_waf update-rule \
  --rule-id "$CSRF_RULE_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=false,Type=ByteMatch,DataId=$URI_SET_ID}"
aws_waf update-rule \
  --rule-id "$CSRF_RULE_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,Predicate={Negated=true,Type=ByteMatch,DataId=$ORIGIN_SET_ID}"

echo "==> WebACL $WEB_ACL_NAME default ALLOW, XSS priority 1, CSRF priority 2"
WEB_ACL_ID="$(aws_waf create-web-acl \
  --name "$WEB_ACL_NAME" \
  --metric-name XSSCSRFWebACL \
  --default-action Type=ALLOW \
  --change-token "$(token)" \
  --query WebACL.WebACLId \
  --output text)"

aws_waf update-web-acl \
  --web-acl-id "$WEB_ACL_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=1,RuleId=$XSS_RULE_ID,Action={Type=BLOCK},Type=REGULAR}"

aws_waf update-web-acl \
  --web-acl-id "$WEB_ACL_ID" \
  --change-token "$(token)" \
  --updates "Action=INSERT,ActivatedRule={Priority=2,RuleId=$CSRF_RULE_ID,Action={Type=BLOCK},Type=REGULAR}"

echo "==> WebACL created: $WEB_ACL_ID"
echo "==> Listing WebACLs:"
aws_waf list-web-acls

echo ""
echo "In production, associate this WebACL with an ALB or CloudFront distribution."
echo "In this lab, traffic on :8080 is enforced by waf-proxy using the same logic."
echo "API used: $WAF_API (AWS WAF Classic). WAFv2 is not available on LocalStack Community."
