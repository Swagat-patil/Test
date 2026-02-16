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

# Cost Information
output "estimated_monthly_cost" {
  description = "Estimated monthly cost breakdown"
  value = <<-EOT
  
  Estimated Monthly Cost (us-east-1):
  ====================================
  MSK Brokers (2x kafka.t3.small):  ~$70/month
  EBS Storage (100GB total):         ~$10/month
  Data Transfer:                     Variable
  KMS:                               ~$1/month
  Secrets Manager:                   ~$0.40/month
  CloudWatch Logs:                   ~$1/month
  ====================================
  TOTAL (approx):                    ~$82/month
  
  💡 Tip: Run 'terraform destroy' when not using to STOP ALL COSTS!
  EOT
}

# Setup Instructions
output "next_steps" {
  description = "What to do next"
  value = <<-EOT
  
  ========================================
  ✅ MSK CLUSTER DEPLOYED SUCCESSFULLY!
  ========================================
  
  Cluster: ${aws_msk_cluster.main.cluster_name}
  Region: ${var.aws_region}
  
  📋 STEP 1: GET YOUR CREDENTIALS
  --------------------------------
  Run this command to retrieve all credentials:
  
  aws secretsmanager get-secret-value \
    --secret-id ${aws_secretsmanager_secret.debezium_creds.name} \
    --region ${var.aws_region} \
    --query SecretString --output text | jq .
  
  Or get them individually:
  terraform output iam_access_key_id
  terraform output iam_secret_access_key
  terraform output iam_role_arn
  terraform output external_id
  
  📋 STEP 2: TEST CONNECTION
  ---------------------------
  # Set credentials
  export AWS_ACCESS_KEY_ID="$(terraform output -raw iam_access_key_id)"
  export AWS_SECRET_ACCESS_KEY="$(terraform output -raw iam_secret_access_key)"
  export AWS_DEFAULT_REGION="${var.aws_region}"
  
  # Test AssumeRole
  aws sts assume-role \
    --role-arn ${aws_iam_role.msk_access.arn} \
    --role-session-name test \
    --external-id ${var.external_id}
  
  📋 STEP 3: DOWNLOAD REQUIRED LIBRARY
  -------------------------------------
  wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.9/aws-msk-iam-auth-1.1.9-all.jar
  
  Copy to your Kafka libs directory
  
  📋 STEP 4: CONFIGURE DEBEZIUM
  -------------------------------
  Bootstrap Servers: ${aws_msk_cluster.main.bootstrap_brokers_public_sasl_iam}
  Port: 9098
  Auth: IAM with AssumeRole
  Role ARN: ${aws_iam_role.msk_access.arn}
  External ID: ${var.external_id}
  
  📋 COST SAVING TIP
  -------------------
  When not using this cluster, destroy it to stop all costs:
  
  terraform destroy
  
  To recreate later:
  
  terraform apply
  
  ========================================
  EOT
}
