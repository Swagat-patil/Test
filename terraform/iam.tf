# =============================================================================
# iam.tf — All IAM resources for the Glenraven CDC Pipeline
#
# Resources created:
#   1. Debezium IAM user + role     — on-prem Debezium authenticates to MSK
#   2. OpenSearch readonly user     — service account: read/search only
#   3. OpenSearch readwrite user    — service account: index + search
#   4. OpenSearch readonly role     — assumed by readonly user, has aoss:APIAccessAll
#   5. OpenSearch readwrite role    — assumed by readwrite user, has aoss:APIAccessAll
#   6. Lambda execution role        — MSK read, DynamoDB rw, OpenSearch write, VPC, logs
#   7. Glenraven existing roles     — optional: attach OpenSearch read policy to any
#                                     pre-existing roles via for_each
# =============================================================================

# =============================================================================
# 1. DEBEZIUM IAM USER + ROLE
# On-prem Debezium uses this user's credentials to assume the MSK access role.
# The role has kafka-cluster:* permissions on the MSK cluster.
# =============================================================================

resource "aws_iam_user" "debezium" {
  name = "${var.cluster_name}-debezium-user"
  path = "/service-accounts/"

  tags = {
    Purpose     = "On-prem Debezium MSK access via IAM auth"
    Environment = "dev"
  }
}

resource "aws_iam_access_key" "debezium" {
  user = aws_iam_user.debezium.name
}

# Role that Debezium assumes — carries the actual MSK permissions
resource "aws_iam_role" "msk_access" {
  name        = "${var.cluster_name}-msk-access-role"
  description = "Role for on-prem Debezium to access MSK via IAM auth"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.debezium.arn }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.external_id
        }
      }
    }]
  })

  tags = { Environment = "dev" }
}

# MSK permissions attached to the Debezium role
resource "aws_iam_role_policy" "msk_access" {
  name = "msk-access-policy"
  role = aws_iam_role.msk_access.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "MSKClusterActions"
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
        Sid    = "MSKTopicActions"
        Effect = "Allow"
        Action = [
          "kafka-cluster:*Topic*",
          "kafka-cluster:WriteData",
          "kafka-cluster:ReadData"
        ]
        Resource = "arn:aws:kafka:${var.aws_region}:${data.aws_caller_identity.current.account_id}:topic/${var.cluster_name}/*"
      },
      {
        Sid    = "MSKGroupActions"
        Effect = "Allow"
        Action = [
          "kafka-cluster:AlterGroup",
          "kafka-cluster:DescribeGroup"
        ]
        Resource = "arn:aws:kafka:${var.aws_region}:${data.aws_caller_identity.current.account_id}:group/${var.cluster_name}/*"
      },
      {
        Sid    = "MSKTransactionalId"
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

# Allow the Debezium user to assume the MSK role
resource "aws_iam_user_policy" "debezium_assume_role" {
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

# =============================================================================
# 2 & 3. OPENSEARCH SERVICE ACCOUNT USERS
# These are human-less accounts used by applications to access OpenSearch.
# Each user assumes its corresponding role which carries the aoss:APIAccessAll policy.
# NOTE: aoss:APIAccessAll (IAM layer) + data access policy (AOSS layer) = full auth.
# =============================================================================

resource "aws_iam_user" "aoss_readonly" {
  name = "${var.project}-aoss-readonly-sa"
  path = "/service-accounts/"

  tags = {
    Project     = var.project
    Environment = "dev"
    Purpose     = "OpenSearch read-only service account"
  }
}

resource "aws_iam_user" "aoss_readwrite" {
  name = "${var.project}-aoss-readwrite-sa"
  path = "/service-accounts/"

  tags = {
    Project     = var.project
    Environment = "dev"
    Purpose     = "OpenSearch read-write service account"
  }
}

resource "aws_iam_access_key" "aoss_readonly" {
  user = aws_iam_user.aoss_readonly.name
}

resource "aws_iam_access_key" "aoss_readwrite" {
  user = aws_iam_user.aoss_readwrite.name
}

# =============================================================================
# 4 & 5. OPENSEARCH IAM ROLES
# Users assume these roles. The roles carry the aoss:APIAccessAll policy
# which allows the HTTPS call to reach OpenSearch Serverless.
# The actual read vs write permission is enforced by the AOSS Data Access Policy
# defined in main.tf (opensearch section).
# =============================================================================

resource "aws_iam_role" "aoss_readonly" {
  name = "${var.project}-aoss-readonly"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.aoss_readonly.arn }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Project = var.project, Environment = "dev" }
}

resource "aws_iam_role" "aoss_readwrite" {
  name = "${var.project}-aoss-readwrite"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.aoss_readwrite.arn }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Project = var.project, Environment = "dev" }
}

# aoss:APIAccessAll on the role — gates the API call at IAM layer
resource "aws_iam_role_policy" "aoss_readonly_api" {
  name = "aoss-api-access"
  role = aws_iam_role.aoss_readonly.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["aoss:APIAccessAll"]
      Resource = "arn:aws:aoss:${var.aws_region}:${data.aws_caller_identity.current.account_id}:collection/*"
    }]
  })
}

resource "aws_iam_role_policy" "aoss_readwrite_api" {
  name = "aoss-api-access"
  role = aws_iam_role.aoss_readwrite.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["aoss:APIAccessAll"]
      Resource = "arn:aws:aoss:${var.aws_region}:${data.aws_caller_identity.current.account_id}:collection/*"
    }]
  })
}

# Allow each user to assume its corresponding role
resource "aws_iam_user_policy" "readonly_assume" {
  name = "assume-aoss-readonly-role"
  user = aws_iam_user.aoss_readonly.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.aoss_readonly.arn
    }]
  })
}

resource "aws_iam_user_policy" "readwrite_assume" {
  name = "assume-aoss-readwrite-role"
  user = aws_iam_user.aoss_readwrite.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.aoss_readwrite.arn
    }]
  })
}

# =============================================================================
# 6. LAMBDA EXECUTION ROLE
# Lambda needs permissions for:
#   - VPC networking (create/delete ENIs to attach to subnets)
#   - CloudWatch Logs (write function logs)
#   - MSK (connect + consume from topics via IAM auth)
#   - DynamoDB (read + write enrichment cache)
#   - OpenSearch Serverless (write CDC events)
# =============================================================================

resource "aws_iam_role" "lambda_role" {
  name        = "${var.project}-lambda-role"
  description = "Execution role for CDC processor Lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Project = var.project, Environment = "dev" }
}

# Managed policy: CloudWatch Logs + VPC ENI management
resource "aws_iam_role_policy_attachment" "lambda_vpc_execution" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# MSK permissions for Event Source Mapping (IAM auth)
resource "aws_iam_role_policy" "lambda_msk" {
  name = "lambda-msk-iam-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "MSKDescribe"
        Effect = "Allow"
        Action = [
          "kafka:DescribeCluster",
          "kafka:DescribeClusterV2",
          "kafka:GetBootstrapBrokers"
        ]
        Resource = aws_msk_cluster.main.arn
      },
      {
        Sid    = "MSKConsume"
        Effect = "Allow"
        Action = [
          "kafka-cluster:Connect",
          "kafka-cluster:DescribeGroup",
          "kafka-cluster:AlterGroup",
          "kafka-cluster:DescribeTopic",
          "kafka-cluster:ReadData",
          "kafka-cluster:DescribeClusterDynamicConfiguration"
        ]
        Resource = [
          aws_msk_cluster.main.arn,
          "${aws_msk_cluster.main.arn}/*"
        ]
      }
    ]
  })
}

# DynamoDB read + write for enrichment cache
resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "lambda-dynamodb-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DynamoDBReadWrite"
      Effect = "Allow"
      Action = [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:BatchGetItem",
        "dynamodb:BatchWriteItem"
      ]
      Resource = [
        aws_dynamodb_table.enrichment_cache.arn,
        "${aws_dynamodb_table.enrichment_cache.arn}/index/*"
      ]
    }]
  })
}

# OpenSearch Serverless write access for Lambda
resource "aws_iam_role_policy" "lambda_opensearch" {
  name = "lambda-opensearch-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "OpenSearchServerlessWrite"
      Effect   = "Allow"
      Action   = ["aoss:APIAccessAll"]
      Resource = "arn:aws:aoss:${var.aws_region}:${data.aws_caller_identity.current.account_id}:collection/*"
    }]
  })
}

# =============================================================================
# 7. GLENRAVEN EXISTING ROLES — attach OpenSearch read access
# Uses for_each so it safely handles an empty list (no roles = no resources)
# Add existing role names to var.glenraven_role_names in terraform.tfvars
# =============================================================================

resource "aws_iam_role_policy" "glenraven_opensearch" {
  for_each = toset(var.glenraven_role_names)

  name = "${var.project}-opensearch-read-access"
  role = each.value

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "OpenSearchServerlessReadAccess"
      Effect   = "Allow"
      Action   = ["aoss:APIAccessAll"]
      Resource = "arn:aws:aoss:${var.aws_region}:${data.aws_caller_identity.current.account_id}:collection/*"
    }]
  })
}
