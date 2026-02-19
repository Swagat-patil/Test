# =============================================================================
# main.tf — Glenraven CDC Pipeline
#
# What this file provisions:
#   1. Terraform + Provider config
#   2. Networking   — VPC, subnets, IGW, route tables, VPC endpoints, SGs
#   3. KMS          — encryption key for MSK
#   4. MSK          — public cluster, IAM auth, TLS, public access via null_resource
#   5. Secrets Mgr  — stores Debezium IAM credentials
#   6. OpenSearch   — serverless collection, encryption/network/data-access policies
#   7. DynamoDB     — enrichment cache table (PAY_PER_REQUEST)
#   8. Lambda       — CDC processor, zipped from lambda_src/, env vars wired up
#   9. Event Source Mapping — MSK → Lambda (IAM auth, one mapping per topic)
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region     = var.aws_region
  access_key = var.access_key
  secret_key = var.secret_key
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Collection name must match exactly in all OpenSearch policy resources
  collection_name = var.project
  prefix          = var.project
  account_id      = data.aws_caller_identity.current.account_id
}

# =============================================================================
# NETWORKING
# =============================================================================

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

resource "aws_internet_gateway" "msk_igw" {
  vpc_id = aws_vpc.msk_vpc.id

  tags = {
    Name        = "${var.cluster_name}-igw"
    Environment = "dev"
  }
}

# Public subnets — MSK brokers live here (required for public MSK)
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

# Free Gateway VPC Endpoints — so Lambda/MSK can reach DynamoDB and S3
# without internet traffic (no NAT cost for these services)
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

# MSK Security Group
# Port 9098 = Kafka IAM auth (SASL IAM over TLS)
# Port 2181 = ZooKeeper
resource "aws_security_group" "msk" {
  name        = "${var.cluster_name}-msk-sg"
  description = "Security group for MSK cluster — IAM auth on 9098"
  vpc_id      = aws_vpc.msk_vpc.id

  ingress {
    description = "Kafka IAM Auth — on-prem Debezium + Lambda"
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

# Lambda Security Group — sits in same VPC, talks to MSK on 9098
resource "aws_security_group" "lambda" {
  name        = "${var.cluster_name}-lambda-sg"
  description = "Security group for Lambda CDC processor"
  vpc_id      = aws_vpc.msk_vpc.id

  egress {
    description = "All outbound — reaches MSK (9098), OpenSearch (443), DynamoDB (via endpoint)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-lambda-sg"
    Environment = "dev"
  }
}

# =============================================================================
# KMS KEY — MSK at-rest encryption
# =============================================================================

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

# =============================================================================
# CLOUDWATCH LOG GROUP — MSK broker logs
# =============================================================================

resource "aws_cloudwatch_log_group" "msk" {
  name              = "/aws/msk/${var.cluster_name}"
  retention_in_days = 3

  tags = {
    Name        = "${var.cluster_name}-logs"
    Environment = "dev"
  }
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.cluster_name}-cdc-processor"
  retention_in_days = 7

  tags = {
    Name        = "${var.cluster_name}-lambda-logs"
    Environment = "dev"
  }
}

# =============================================================================
# MSK CONFIGURATION
# =============================================================================

resource "aws_msk_configuration" "main" {
  name           = "${var.cluster_name}-config"
  kafka_versions = [var.kafka_version]

  server_properties = <<-PROPERTIES
    auto.create.topics.enable=true
    delete.topic.enable=true
    log.retention.hours=24
    default.replication.factor=2
    min.insync.replicas=1
    num.partitions=3
  PROPERTIES
}

# =============================================================================
# MSK CLUSTER
# Step 1: Create with public_access = DISABLED (AWS requires this)
# Step 2: null_resource enables public access after cluster is ACTIVE
# This mirrors exactly what the AWS Console does internally.
# =============================================================================

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

    # Must start DISABLED — public access is enabled after creation via null_resource below
    connectivity_info {
      public_access {
        type = "DISABLED"
      }
    }
  }

  # IAM authentication — no passwords, Debezium uses AWS credentials (SigV4)
  client_authentication {
    sasl {
      iam = true
    }
  }

  encryption_info {
    encryption_at_rest_kms_key_arn = aws_kms_key.msk.arn

    encryption_in_transit {
      client_broker = "TLS"     # Force TLS — reject plaintext
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

# Enable public access AFTER cluster is fully ACTIVE
# AWS requires this two-step approach — cannot set SERVICE_PROVIDED_EIPS on creation
resource "null_resource" "enable_public_access" {
  depends_on = [aws_msk_cluster.main]

  provisioner "local-exec" {
    command = <<-EOT
      echo "Waiting for MSK cluster to be ACTIVE..."
      aws kafka wait cluster-active \
        --cluster-arn ${aws_msk_cluster.main.arn} \
        --region ${var.aws_region}

      echo "Enabling public access..."
      aws kafka update-connectivity \
        --cluster-arn ${aws_msk_cluster.main.arn} \
        --region ${var.aws_region} \
        --connectivity-info '{"PublicAccess":{"Type":"SERVICE_PROVIDED_EIPS"}}' \
        --current-version $(aws kafka describe-cluster \
          --cluster-arn ${aws_msk_cluster.main.arn} \
          --region ${var.aws_region} \
          --query 'ClusterInfo.CurrentVersion' \
          --output text)

      echo "Waiting for public access update to complete..."
      aws kafka wait cluster-active \
        --cluster-arn ${aws_msk_cluster.main.arn} \
        --region ${var.aws_region}
      echo "Public access enabled!"
    EOT
  }
}

# =============================================================================
# SECRETS MANAGER — store Debezium credentials for safe retrieval
# =============================================================================

resource "aws_secretsmanager_secret" "debezium_creds" {
  name        = "${var.cluster_name}-debezium-credentials"
  description = "IAM credentials for on-prem Debezium to connect to MSK"

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
    NOTE                  = "Run: aws kafka get-bootstrap-brokers --cluster-arn <CLUSTER_ARN> to get broker endpoints"
  })
}

# =============================================================================
# OPENSEARCH SERVERLESS
# Order matters: encryption → network → collection → data access policies
# =============================================================================

# 1. Encryption policy (must exist before collection)
resource "aws_opensearchserverless_security_policy" "encryption" {
  name        = "${local.prefix}-encryption"
  type        = "encryption"
  description = "AWS-managed key encryption for ${local.prefix} collection"

  policy = jsonencode({
    AWSOwnedKey = true
    Rules = [{
      Resource     = ["collection/${local.collection_name}"]
      ResourceType = "collection"
    }]
  })
}

# 2. Network policy — public access so Lambda (via VPC) and on-prem clients can reach it
resource "aws_opensearchserverless_security_policy" "network" {
  name        = "${local.prefix}-network"
  type        = "network"
  description = "Public HTTPS access to collection and dashboards (dev)"

  policy = jsonencode([{
    AllowFromPublic = true
    Rules = [
      {
        Resource     = ["collection/${local.collection_name}"]
        ResourceType = "collection"
      },
      {
        Resource     = ["collection/${local.collection_name}"]
        ResourceType = "dashboard"
      }
    ]
  }])
}

# 3. Collection (depends on both policies above)
resource "aws_opensearchserverless_collection" "this" {
  name = local.collection_name
  type = "SEARCH"

  depends_on = [
    aws_opensearchserverless_security_policy.encryption,
    aws_opensearchserverless_security_policy.network,
  ]

  tags = {
    Project     = var.project
    Environment = "dev"
  }
}

# 4a. Data access policy — Read-Only (for readonly role + Glenraven roles)
resource "aws_opensearchserverless_access_policy" "readonly" {
  name        = "${local.prefix}-aoss-readonly"
  type        = "data"
  description = "Read-only: search documents and describe indexes"

  policy = jsonencode([{
    Description = "Read-only access"
    Principal   = [aws_iam_role.aoss_readonly.arn]
    Rules = [
      {
        ResourceType = "collection"
        Resource     = ["collection/${local.collection_name}"]
        Permission   = ["aoss:DescribeCollectionItems"]
      },
      {
        ResourceType = "index"
        Resource     = ["index/${local.collection_name}/*"]
        Permission   = ["aoss:ReadDocument", "aoss:DescribeIndex"]
      }
    ]
  }])
}

# 4b. Data access policy — Read-Write (for readwrite role + Lambda role)
resource "aws_opensearchserverless_access_policy" "readwrite" {
  name        = "${local.prefix}-aoss-readwrite"
  type        = "data"
  description = "Read-write: full index operations — Lambda CDC writer + readwrite service account"

  policy = jsonencode([{
    Description = "Read-write access"
    Principal = [
      aws_iam_role.aoss_readwrite.arn,
      aws_iam_role.lambda_role.arn     # Lambda also needs write access to index CDC events
    ]
    Rules = [
      {
        ResourceType = "collection"
        Resource     = ["collection/${local.collection_name}"]
        Permission   = ["aoss:DescribeCollectionItems"]
      },
      {
        ResourceType = "index"
        Resource     = ["index/${local.collection_name}/*"]
        Permission = [
          "aoss:ReadDocument",
          "aoss:WriteDocument",
          "aoss:DescribeIndex",
          "aoss:CreateIndex",
          "aoss:DeleteIndex",
          "aoss:UpdateIndex"
        ]
      }
    ]
  }])
}

# =============================================================================
# DYNAMODB — Enrichment / Reference Lookup Cache
#
# Key design:
#   PK = "TABLE#<oracle_table>"   e.g. "TABLE#CUSTOMERS"
#   SK = "ID#<primary_key>"       e.g. "ID#12345"
#
# Lambda reads this table to enrich CDC events before writing to OpenSearch.
# Lambda also writes back to keep reference data up-to-date.
# =============================================================================

resource "aws_dynamodb_table" "enrichment_cache" {
  name         = "${var.project}-enrichment-cache"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PK"
  range_key    = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  # TTL — Lambda sets this field (Unix epoch) to auto-expire stale reference data
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Environment = "dev"
    Project     = var.project
  }
}

# =============================================================================
# LAMBDA — CDC Processor
# Reads Debezium events from MSK, writes to OpenSearch + DynamoDB
# =============================================================================

# Install pip dependencies into lambda_src/ then package as ZIP
# Runs: pip install -r requirements.txt -t ./lambda_src/
# so that opensearch-py and its deps are bundled into the deployment package
resource "null_resource" "pip_install" {
  triggers = {
    requirements = filemd5("${path.module}/lambda_src/requirements.txt")
    handler      = filemd5("${path.module}/lambda_src/handler.py")
  }

  provisioner "local-exec" {
    command = "pip install -r ${path.module}/lambda_src/requirements.txt -t ${path.module}/lambda_src/ --quiet --upgrade"
  }
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src"
  output_path = "${path.module}/lambda_cdc_processor.zip"

  depends_on = [null_resource.pip_install]
}

resource "aws_lambda_function" "cdc_processor" {
  function_name    = "${var.cluster_name}-cdc-processor"
  description      = "CDC processor: MSK Debezium events → OpenSearch Serverless + DynamoDB"
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_role.arn
  timeout          = 300       # 5 min — MSK batch processing can be slow
  memory_size      = 512
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  # Lambda in the same VPC as MSK so it can reach the brokers on port 9098
  vpc_config {
    subnet_ids         = aws_subnet.public[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      # handler.py reads OPENSEARCH_HOST as hostname only (no https://)
      # We strip the scheme from the collection endpoint here
      OPENSEARCH_HOST     = replace(aws_opensearchserverless_collection.this.collection_endpoint, "https://", "")
      OPENSEARCH_PORT     = "443"
      OPENSEARCH_SCHEME   = "https"
      OPENSEARCH_AUTH     = "iam"   # use IAM / SigV4 — no basic auth needed

      # handler.py reads DYNAMODB_TABLE (not DYNAMODB_TABLE_NAME)
      DYNAMODB_TABLE      = aws_dynamodb_table.enrichment_cache.name

      # Standard AWS Lambda env var — already injected by Lambda runtime,
      # listed here explicitly so handler.py's fallback default is never used
      AWS_REGION_OVERRIDE = var.aws_region   # handler uses AWS_REGION which Lambda sets automatically

      LOG_LEVEL           = "INFO"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    null_resource.enable_public_access   # MSK must be public before ESM works
  ]

  tags = {
    Name        = "${var.cluster_name}-cdc-processor"
    Environment = "dev"
    Project     = var.project
  }
}

# =============================================================================
# EVENT SOURCE MAPPING — MSK → Lambda
#
# How it works:
#   - AWS Lambda service polls MSK on your behalf
#   - Uses Lambda execution role's IAM permissions to authenticate (no secret needed)
#   - When messages arrive on the topic, Lambda is invoked with a batch
#   - One mapping is created per topic in var.kafka_topics
#
# starting_position = TRIM_HORIZON → process from oldest available message
# Change to LATEST if you only want new messages going forward
# =============================================================================

resource "aws_lambda_event_source_mapping" "msk_to_lambda" {
  for_each = toset(var.kafka_topics)

  event_source_arn  = aws_msk_cluster.main.arn
  function_name     = aws_lambda_function.cdc_processor.arn
  topics            = [each.value]
  starting_position = "TRIM_HORIZON"

  # Batch tuning — adjust for throughput vs latency
  batch_size                         = 100  # max records per Lambda invocation
  maximum_batching_window_in_seconds = 5    # wait up to 5s to fill a batch

  # Debezium op filter — only forward insert/update/delete/snapshot events
  # c=create, u=update, d=delete, r=read(snapshot)
  filter_criteria {
    filter {
      pattern = jsonencode({
        value = {
          op = ["c", "u", "d", "r"]
        }
      })
    }
  }

  # Consumer group ID — MSK uses this to track Lambda's read offset per topic
  amazon_managed_kafka_event_source_config {
    consumer_group_id = "${var.project}-cdc-consumer"
  }

  depends_on = [null_resource.enable_public_access]
}
