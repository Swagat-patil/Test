# terraform.tfvars - Customize Your Configuration

# AWS Region
aws_region = "us-east-1"

# Cluster Name
cluster_name = "dev-msk-cluster"

# VPC CIDR
vpc_cidr = "10.0.0.0/16"

# Kafka Version
kafka_version = "3.6.0"

# EBS Volume Size per Broker (GB)
broker_volume_size = 10


external_id = "my-msk-2024"


allowed_cidr_blocks = ["203.0.113.45/32"]


