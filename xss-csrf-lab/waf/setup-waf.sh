#!/bin/bash
set -e

ENDPOINT="http://localhost:4566"
REGION="us-east-1"

echo "==> Creating WebACL with XSS & CSRF rules..."

# ساخت Web ACL همراه با هر دو قاعده
aws --endpoint-url=$ENDPOINT --region=$REGION wafv2 create-web-acl \
  --name "XSS-CSRF-Protection" \
  --scope "REGIONAL" \
  --default-action "Allow={}" \
  --visibility-config \
      SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=XSSCSRFWebACL \
  --rules "[$(cat rules/xss-rule.json),$(cat rules/csrf-rule.json)]"

echo "==> WebACL created successfully."

echo "==> Listing WebACLs:"
aws --endpoint-url=$ENDPOINT --region=$REGION wafv2 list-web-acls  --scope "REGIONAL"
