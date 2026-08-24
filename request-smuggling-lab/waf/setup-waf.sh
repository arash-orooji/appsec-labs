#!/bin/bash
set -e

ENDPOINT="${AWS_ENDPOINT_URL:-http://localhost:4566}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RULES_DIR="${SCRIPT_DIR}/rules"

# LocalStack init mounts rules at a fixed path
if [ -d /etc/localstack/init/ready.d/waf/rules ]; then
  RULES_DIR=/etc/localstack/init/ready.d/waf/rules
elif [ ! -d "$RULES_DIR" ] && [ -d "${SCRIPT_DIR}/waf/rules" ]; then
  RULES_DIR="${SCRIPT_DIR}/waf/rules"
fi

echo "==> Creating WebACL: Request-Smuggling-Protection"
echo "    endpoint=$ENDPOINT region=$REGION rules=$RULES_DIR"

RULES_JSON="[$(cat "$RULES_DIR/block-cl-te.json"),$(cat "$RULES_DIR/block-te-obfuscation.json"),$(cat "$RULES_DIR/block-malformed-cl.json")]"

aws --endpoint-url="$ENDPOINT" --region="$REGION" wafv2 create-web-acl \
  --name "Request-Smuggling-Protection" \
  --scope "REGIONAL" \
  --default-action "Allow={}" \
  --description "Blocks HTTP request smuggling indicators (CL.TE / TE obfuscation / duplicate CL)" \
  --visibility-config \
    SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=RequestSmugglingWebACL \
  --rules "$RULES_JSON"

echo "==> WebACL created."
echo "==> Listing WebACLs:"
aws --endpoint-url="$ENDPOINT" --region="$REGION" wafv2 list-web-acls --scope "REGIONAL"

echo ""
echo "In production, associate this WebACL with an ALB or CloudFront distribution."
echo "In this lab, traffic on :8080 is enforced by waf-proxy using the same logic."
