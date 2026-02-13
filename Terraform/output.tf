output "opensearch_endpoint" {
  value = aws_opensearchserverless_collection.this.collection_endpoint
}

output "opensearch_dashboard_url" {
  value = aws_opensearchserverless_collection.this.dashboard_endpoint
}

output "aoss_readonly_role_arn" {
  value = aws_iam_role.aoss_readonly.arn
}

output "aoss_readwrite_role_arn" {
  value = aws_iam_role.aoss_readwrite.arn
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.enrichment_cache.name
}
