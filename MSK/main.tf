terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "6.3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  access_key = var.access_key
  secret_key = var.secret_key
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# VPC

resource "aws_vpc" "msk_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.cluster_name}-vpc"
    Environment = "dev"
    ManagedBy   = "Terraform"
  }
}

# Internet Gateway

resource "aws_internet_gateway" "msk_igw" {
  vpc_id = aws_vpc.msk_vpc.id

  tags = {
    Name        = "${var.cluster_name}-igw"
    Environment = "dev"
  }
}

# Public Subnets (same as your manual setup)


resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.msk_vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.cluster_name}-public-subnet-${count.index + 1}"
    Environment = "dev"
    Type        = "public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.msk_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.msk_igw.id
  }

  tags = {
    Name        = "${var.cluster_name}-public-rt"
    Environment = "dev"
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# VPC Gateway Endpoints 

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.msk_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id]

  tags = {
    Name        = "${var.cluster_name}-dynamodb-endpoint"
    Environment = "dev"
    Cost        = "FREE"
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.msk_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id]

  tags = {
    Name        = "${var.cluster_name}-s3-endpoint"
    Environment = "dev"
    Cost        = "FREE"
  }
}

# Security Group

resource "aws_security_group" "msk" {
  name        = "${var.cluster_name}-msk-sg"
  description = "Security group for MSK cluster"
  vpc_id      = aws_vpc.msk_vpc.id

  ingress {
    description = "Kafka IAM Auth"
    from_port   = 9098
    to_port     = 9098
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  ingress {
    description = "ZooKeeper"
    from_port   = 2181
    to_port     = 2181
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-msk-sg"
    Environment = "dev"
  }
}

# KMS Key

resource "aws_kms_key" "msk" {
  description             = "KMS key for MSK cluster encryption"
  deletion_window_in_days = 7

  tags = {
    Name        = "${var.cluster_name}-kms-key"
    Environment = "dev"
  }
}

resource "aws_kms_alias" "msk" {
  name          = "alias/${var.cluster_name}"
  target_key_id = aws_kms_key.msk.key_id
}

# CloudWatch Log Group

resource "aws_cloudwatch_log_group" "msk" {
  name              = "/aws/msk/${var.cluster_name}"
  retention_in_days = 3

  tags = {
    Name        = "${var.cluster_name}-logs"
    Environment = "dev"
  }
}


# MSK Configuration

resource "aws_msk_configuration" "main" {
  name           = "${var.cluster_name}-config"
  kafka_versions = [var.kafka_version]

  server_properties = <<PROPERTIES
auto.create.topics.enable=true
delete.topic.enable=true
log.retention.hours=24
default.replication.factor=2
min.insync.replicas=1
num.partitions=3
PROPERTIES
}

# MSK Cluster
# Step 1: Create WITHOUT public access first
# Step 2: Enable public access after creation

resource "aws_msk_cluster" "main" {
  cluster_name           = var.cluster_name
  kafka_version          = var.kafka_version
  number_of_broker_nodes = 2

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = aws_subnet.public[*].id
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info {
        volume_size = var.broker_volume_size
      }
    }

    connectivity_info {
      public_access {
        type = "DISABLED" # Start with DISABLED
      }
    }
  }

  client_authentication {
    sasl {
      iam = true
    }
  }

  encryption_info {
    encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn

    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.main.arn
    revision = aws_msk_configuration.main.latest_revision
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk.name
      }
    }
  }

  tags = {
    Name        = var.cluster_name
    Environment = "dev"
    CostCenter  = "development"
  }
}

# IAM User


resource "aws_iam_user" "debezium" {
  name = "${var.cluster_name}-debezium-user"
  path = "/service-accounts/"

  tags = {
    Purpose     = "On-prem Debezium MSK access"
    Environment = "dev"
  }
}

resource "aws_iam_access_key" "debezium" {
  user = aws_iam_user.debezium.name
}


# IAM Role


resource "aws_iam_role" "msk_access" {
  name        = "${var.cluster_name}-msk-access-role"
  description = "Role for on-prem Debezium to access MSK"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_user.debezium.arn
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.external_id
        }
      }
    }]
  })

  tags = {
    Environment = "dev"
  }
}

resource "aws_iam_role_policy" "msk_access" {
  name = "msk-access-policy"
  role = aws_iam_role.msk_access.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:Connect",
          "kafka-cluster:DescribeCluster",
          "kafka-cluster:AlterCluster",
          "kafka-cluster:DescribeClusterDynamicConfiguration"
        ]
        Resource = aws_msk_cluster.main.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:*Topic*",
          "kafka-cluster:WriteData",
          "kafka-cluster:ReadData"
        ]
        Resource = "arn:aws:kafka:${var.aws_region}:${data.aws_caller_identity.current.account_id}:topic/${var.cluster_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:AlterGroup",
          "kafka-cluster:DescribeGroup"
        ]
        Resource = "arn:aws:kafka:${var.aws_region}:${data.aws_caller_identity.current.account_id}:group/${var.cluster_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:WriteDataIdempotently",
          "kafka-cluster:DescribeTransactionalId",
          "kafka-cluster:AlterTransactionalId"
        ]
        Resource = "arn:aws:kafka:${var.aws_region}:${data.aws_caller_identity.current.account_id}:transactional-id/${var.cluster_name}/*"
      }
    ]
  })
}

resource "aws_iam_user_policy" "assume_role" {
  name = "assume-msk-role"
  user = aws_iam_user.debezium.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.msk_access.arn
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.external_id
        }
      }
    }]
  })
}

# Secrets Manager


resource "aws_secretsmanager_secret" "debezium_creds" {
  name        = "${var.cluster_name}-debezium-credentials"
  description = "IAM credentials for on-prem Debezium"

  tags = {
    Environment = "dev"
  }
}

resource "aws_secretsmanager_secret_version" "debezium_creds" {
  secret_id  = aws_secretsmanager_secret.debezium_creds.id
  depends_on = [null_resource.enable_public_access]

  secret_string = jsonencode({
    AWS_ACCESS_KEY_ID     = aws_iam_access_key.debezium.id
    AWS_SECRET_ACCESS_KEY = aws_iam_access_key.debezium.secret
    AWS_REGION            = var.aws_region
    ROLE_ARN              = aws_iam_role.msk_access.arn
    EXTERNAL_ID           = var.external_id
    CLUSTER_ARN           = aws_msk_cluster.main.arn
    NOTE                  = "Get bootstrap servers: aws kafka get-bootstrap-brokers --cluster-arn CLUSTER_ARN"
  })
}
