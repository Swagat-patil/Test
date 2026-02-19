# =============================================================================
# variable.tf — All input variables for the Glenraven CDC Pipeline
# =============================================================================

# =============================================================================
# AWS PROVIDER
# =============================================================================

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "access_key" {
  description = "AWS access key (use environment variables or IAM role in production)"
  type        = string
  sensitive   = true
}

variable "secret_key" {
  description = "AWS secret key (use environment variables or IAM role in production)"
  type        = string
  sensitive   = true
}

# =============================================================================
# PROJECT / NAMING
# =============================================================================

variable "project" {
  description = "Project name — used as prefix for OpenSearch collection, DynamoDB, IAM resources"
  type        = string
  default     = "dev-app"
}

variable "cluster_name" {
  description = "MSK cluster name — used as prefix for VPC, subnets, SGs, IAM, secrets"
  type        = string
  default     = "dev-msk-cluster"
}

# =============================================================================
# NETWORKING
# =============================================================================

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "allowed_cidr_blocks" {
  description = <<-EOT
    CIDR blocks allowed inbound on MSK port 9098 (IAM auth).
    Set to your on-prem Oracle/Debezium host's public IP.
    Run: curl ifconfig.me  on your on-prem host to find it.
  EOT
  type        = list(string)
  default     = ["203.0.113.45/32"]   # Replace with your real on-prem IP!
}

# =============================================================================
# MSK
# =============================================================================

variable "kafka_version" {
  description = "Apache Kafka version for MSK"
  type        = string
  default     = "3.6.0"
}

variable "broker_volume_size" {
  description = "EBS volume size in GB per MSK broker (10 GB is fine for dev)"
  type        = number
  default     = 10
}

variable "kafka_topics" {
  description = <<-EOT
    Kafka topic names that Debezium publishes CDC events to.
    One Lambda Event Source Mapping is created per topic.
    Debezium topic format: <server_name>.<schema>.<table>
  EOT
  type        = list(string)
  default     = ["oracle.cdc.events"]
}

variable "external_id" {
  description = "External ID for the Debezium AssumeRole — change to something unique per environment"
  type        = string
  sensitive   = true
  default     = "my-msk-2024"
}

# =============================================================================
# OPENSEARCH SERVERLESS
# =============================================================================

variable "opensearch_index_name" {
  description = "Default OpenSearch index to write CDC events into"
  type        = string
  default     = "cdc-events"
}

# =============================================================================
# DYNAMODB
# =============================================================================

variable "reference_tables" {
  description = <<-EOT
    Comma-separated Oracle table names whose CDC events should be
    cached in DynamoDB for Lambda enrichment lookups.
    Example: ["CUSTOMERS", "PRODUCTS", "ACCOUNTS"]
  EOT
  type        = list(string)
  default     = []
}

# =============================================================================
# GLENRAVEN EXISTING ROLES
# =============================================================================

variable "glenraven_role_names" {
  description = <<-EOT
    Names of existing IAM roles used by Glenraven applications.
    Each role will receive an inline policy with aoss:APIAccessAll
    so they can access the OpenSearch Serverless collection.
    Leave empty [] if no existing roles need access.
  EOT
  type        = list(string)
  default     = []
  # Example: ["glenraven-app-role", "glenraven-worker-role"]
}
