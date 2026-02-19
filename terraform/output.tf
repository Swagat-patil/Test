# =============================================================================
# output.tf — All outputs for the Glenraven CDC Pipeline
#
# To see all non-sensitive outputs:
#   terraform output
#
# To retrieve a sensitive value:
#   terraform output -raw <output_name>
#
# Example:
#   terraform output -raw iam_secret_access_key
#   terraform output -raw aoss_readwrite_secret_access_key
#   terraform output -raw bootstrap_brokers_public_iam
# =============================================================================

# =============================================================================
# NETWORKING
# =============================================================================

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.msk_vpc.id
}

output "subnet_ids" {
  description = "Public subnet IDs where MSK brokers and Lambda are deployed"
  value       = aws_subnet.public[*].id
}

output "security_group_id" {
  description = "MSK security group ID"
  value       = aws_security_group.msk.id
}

# =============================================================================
# MSK
# =============================================================================

output "msk_cluster_arn" {
  description = "ARN of the MSK cluster"
  value       = aws_msk_cluster.main.arn
}

output "msk_cluster_name" {
  description = "Name of the MSK cluster"
  value       = aws_msk_cluster.main.cluster_name
}

output "bootstrap_brokers_public_iam" {
  description = "Public bootstrap broker endpoints for IAM auth (port 9098) — use in Debezium connector config"
  value       = aws_msk_cluster.main.bootstrap_brokers_public_sasl_iam
  sensitive   = true
}

output "zookeeper_connect_string" {
  description = "ZooKeeper connection string"
  value       = aws_msk_cluster.main.zookeeper_connect_string
}

# =============================================================================
# DEBEZIUM IAM CREDENTIALS
# =============================================================================

output "iam_user_name" {
  description = "IAM username for on-prem Debezium"
  value       = aws_iam_user.debezium.name
}

output "iam_user_arn" {
  description = "IAM user ARN for on-prem Debezium"
  value       = aws_iam_user.debezium.arn
}

output "iam_access_key_id" {
  description = "Debezium IAM user access key ID"
  value       = aws_iam_access_key.debezium.id
  sensitive   = true
}

output "iam_secret_access_key" {
  description = "Debezium IAM user secret access key"
  value       = aws_iam_access_key.debezium.secret
  sensitive   = true
}

output "iam_role_arn" {
  description = "IAM role ARN for MSK access (Debezium assumes this)"
  value       = aws_iam_role.msk_access.arn
}

output "external_id" {
  description = "External ID required when Debezium assumes the MSK role"
  value       = var.external_id
  sensitive   = true
}

output "secrets_manager_secret_name" {
  description = "Secrets Manager secret containing all Debezium credentials"
  value       = aws_secretsmanager_secret.debezium_creds.name
}

output "secrets_manager_secret_arn" {
  description = "Secrets Manager secret ARN"
  value       = aws_secretsmanager_secret.debezium_creds.arn
}

# =============================================================================
# OPENSEARCH SERVERLESS
# =============================================================================

output "opensearch_endpoint" {
  description = "OpenSearch Serverless HTTPS endpoint — set in Lambda env var OPENSEARCH_ENDPOINT"
  value       = aws_opensearchserverless_collection.this.collection_endpoint
}

output "opensearch_dashboard_url" {
  description = "OpenSearch Dashboards URL for browsing/querying indexed data"
  value       = aws_opensearchserverless_collection.this.dashboard_endpoint
}

output "aoss_readonly_role_arn" {
  description = "ARN of the read-only OpenSearch IAM role"
  value       = aws_iam_role.aoss_readonly.arn
}

output "aoss_readwrite_role_arn" {
  description = "ARN of the read-write OpenSearch IAM role"
  value       = aws_iam_role.aoss_readwrite.arn
}

output "aoss_readonly_user_arn" {
  description = "ARN of the read-only OpenSearch service account user"
  value       = aws_iam_user.aoss_readonly.arn
}

output "aoss_readwrite_user_arn" {
  description = "ARN of the read-write OpenSearch service account user"
  value       = aws_iam_user.aoss_readwrite.arn
}

output "aoss_readonly_access_key_id" {
  description = "Access key ID for the read-only OpenSearch service account"
  value       = aws_iam_access_key.aoss_readonly.id
  sensitive   = true
}

output "aoss_readonly_secret_access_key" {
  description = "Secret access key for the read-only OpenSearch service account"
  value       = aws_iam_access_key.aoss_readonly.secret
  sensitive   = true
}

output "aoss_readwrite_access_key_id" {
  description = "Access key ID for the read-write OpenSearch service account"
  value       = aws_iam_access_key.aoss_readwrite.id
  sensitive   = true
}

output "aoss_readwrite_secret_access_key" {
  description = "Secret access key for the read-write OpenSearch service account"
  value       = aws_iam_access_key.aoss_readwrite.secret
  sensitive   = true
}

# =============================================================================
# DYNAMODB
# =============================================================================

output "dynamodb_table_name" {
  description = "DynamoDB enrichment cache table name"
  value       = aws_dynamodb_table.enrichment_cache.name
}

output "dynamodb_table_arn" {
  description = "DynamoDB enrichment cache table ARN"
  value       = aws_dynamodb_table.enrichment_cache.arn
}

# =============================================================================
# LAMBDA
# =============================================================================

output "lambda_function_name" {
  description = "CDC processor Lambda function name"
  value       = aws_lambda_function.cdc_processor.function_name
}

output "lambda_function_arn" {
  description = "CDC processor Lambda function ARN"
  value       = aws_lambda_function.cdc_processor.arn
}

output "lambda_role_arn" {
  description = "Lambda execution role ARN"
  value       = aws_iam_role.lambda_role.arn
}

output "event_source_mapping_ids" {
  description = "MSK Event Source Mapping IDs (one per topic)"
  value       = { for k, v in aws_lambda_event_source_mapping.msk_to_lambda : k => v.id }
}
