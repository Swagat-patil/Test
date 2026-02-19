# =============================================================================
# terraform.tfvars — Glenraven CDC Pipeline Configuration
#
# IMPORTANT: Never commit this file to git — it contains secrets.
# Add terraform.tfvars to your .gitignore
# =============================================================================

# ── AWS Provider ─────────────────────────────────────────────────────────────
aws_region = "us-east-1"
access_key = "YOUR_AWS_ACCESS_KEY_HERE"       # Replace with your key
secret_key = "YOUR_AWS_SECRET_KEY_HERE"       # Replace with your secret

# ── Naming ────────────────────────────────────────────────────────────────────
# cluster_name → used for MSK, VPC, subnets, security groups, secrets
cluster_name = "dev-msk-cluster"

# project → used for OpenSearch collection, DynamoDB table, IAM users/roles
project      = "dev-app"

# ── Networking ────────────────────────────────────────────────────────────────
vpc_cidr = "10.0.0.0/16"

# Replace with your actual on-prem Oracle Exadata / Debezium host public IP
# Run this on your on-prem host to find its public IP: curl ifconfig.me
allowed_cidr_blocks = ["203.0.113.45/32"]

# ── MSK ───────────────────────────────────────────────────────────────────────
kafka_version      = "3.6.0"
broker_volume_size = 10   # GB per broker (10 is fine for dev)

# Kafka topic names Debezium publishes to
# Format: <debezium_server_name>.<oracle_schema>.<oracle_table>
kafka_topics = [
  "oracle.cdc.events",          # catch-all topic
  # "oracle.PUBLIC.CUSTOMERS",  # uncomment for per-table topics
  # "oracle.PUBLIC.ORDERS",
]

# Unique external ID for the Debezium AssumeRole — keep this secret
external_id = "my-msk-2024"

# ── OpenSearch ────────────────────────────────────────────────────────────────
opensearch_index_name = "cdc-events"

# ── DynamoDB ──────────────────────────────────────────────────────────────────
# Oracle table names to cache in DynamoDB for Lambda enrichment lookups
# Lambda writes these tables' CDC events to DynamoDB AND OpenSearch
reference_tables = []   # e.g. ["CUSTOMERS", "PRODUCTS", "ACCOUNTS"]

# ── Glenraven Existing Roles ──────────────────────────────────────────────────
# Names of any existing IAM roles that need OpenSearch read access
# Leave empty if none. Terraform will attach aoss:APIAccessAll to each.
glenraven_role_names = []
# Example: glenraven_role_names = ["glenraven-app-role", "glenraven-api-role"]
