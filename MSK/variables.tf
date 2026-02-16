# variables.tf - Input Variables

variable "aws_region" {
  description = "AWS region for MSK cluster"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "Name of the MSK cluster"
  type        = string
  default     = "dev-msk-cluster"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "kafka_version" {
  description = "Kafka version"
  type        = string
  default     = "3.5.1"
}

variable "broker_volume_size" {
  description = "EBS volume size for each broker in GB"
  type        = number
  default     = 10 # Smaller for dev
}

variable "external_id" {
  description = "External ID for AssumeRole (change this to something unique!)"
  type        = string
  default     = "dev-msk-2024"
  sensitive   = true
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to connect to MSK (your office/on-prem IP)"
  type        = list(string)
  default     = ["203.0.113.0/24"] # CHANGE THIS to your actual IP in production!
  
  # Example: ["203.0.113.0/24", "198.51.100.50/32"]
  # To get your IP: curl ifconfig.me
}
