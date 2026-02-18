output "opensearch_endpoint" {
  description = "OpenSearch Serverless collection endpoint"
  value       = aws_opensearchserverless_collection.this.collection_endpoint
}

output "opensearch_dashboard_url" {
  description = "OpenSearch Dashboards URL"
  value       = aws_opensearchserverless_collection.this.dashboard_endpoint
}

output "aoss_readonly_role_arn" {
  description = "ARN of the read-only IAM role"
  value       = aws_iam_role.aoss_readonly.arn
}

output "aoss_readwrite_role_arn" {
  description = "ARN of the read-write IAM role"
  value       = aws_iam_role.aoss_readwrite.arn
}

output "aoss_readonly_user_arn" {
  description = "ARN of the read-only service account IAM user"
  value       = aws_iam_user.aoss_readonly.arn
}

output "aoss_readwrite_user_arn" {
  description = "ARN of the read-write service account IAM user"
  value       = aws_iam_user.aoss_readwrite.arn
}

output "aoss_readonly_access_key_id" {
  description = "Access key ID for the read-only service account"
  value       = aws_iam_access_key.aoss_readonly.id
  sensitive   = true
}

output "aoss_readonly_secret_access_key" {
  description = "Secret access key for the read-only service account"
  value       = aws_iam_access_key.aoss_readonly.secret
  sensitive   = true
}

output "aoss_readwrite_access_key_id" {
  description = "Access key ID for the read-write service account"
  value       = aws_iam_access_key.aoss_readwrite.id
  sensitive   = true
}

output "aoss_readwrite_secret_access_key" {
  description = "Secret access key for the read-write service account"
  value       = aws_iam_access_key.aoss_readwrite.secret
  sensitive   = true
}

output "dynamodb_table_name" {
  description = "DynamoDB enrichment cache table name"
  value       = aws_dynamodb_table.enrichment_cache.name
}
