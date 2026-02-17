# outputs.tf - Output Values

output "msk_cluster_arn" {
  description = "ARN of the MSK cluster"
  value       = aws_msk_cluster.main.arn
}

output "msk_cluster_name" {
  description = "Name of the MSK cluster"
  value       = aws_msk_cluster.main.cluster_name
}

output "bootstrap_brokers_public_iam" {
  description = "Public bootstrap brokers with IAM auth (port 9098)"
  value       = aws_msk_cluster.main.bootstrap_brokers_public_sasl_iam
}

output "zookeeper_connect_string" {
  description = "ZooKeeper connection string"
  value       = aws_msk_cluster.main.zookeeper_connect_string
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.msk_vpc.id
}

output "subnet_ids" {
  description = "Subnet IDs where MSK brokers are deployed"
  value       = aws_subnet.public[*].id
}

output "security_group_id" {
  description = "MSK security group ID"
  value       = aws_security_group.msk.id
}

# IAM Outputs
output "iam_user_name" {
  description = "IAM user name for on-prem access"
  value       = aws_iam_user.debezium.name
}

output "iam_user_arn" {
  description = "IAM user ARN"
  value       = aws_iam_user.debezium.arn
}

output "iam_access_key_id" {
  description = "IAM user access key ID"
  value       = aws_iam_access_key.debezium.id
  sensitive   = true
}

output "iam_secret_access_key" {
  description = "IAM user secret access key"
  value       = aws_iam_access_key.debezium.secret
  sensitive   = true
}

output "iam_role_arn" {
  description = "IAM role ARN for MSK access"
  value       = aws_iam_role.msk_access.arn
}

output "external_id" {
  description = "External ID for AssumeRole"
  value       = var.external_id
  sensitive   = true
}

output "secrets_manager_secret_name" {
  description = "Secrets Manager secret name containing all credentials"
  value       = aws_secretsmanager_secret.debezium_creds.name
}

output "secrets_manager_secret_arn" {
  description = "Secrets Manager secret ARN"
  value       = aws_secretsmanager_secret.debezium_creds.arn
}

