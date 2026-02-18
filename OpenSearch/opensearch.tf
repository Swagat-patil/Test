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
}

locals {
  collection_name = var.project
}


# Encryption Policy

resource "aws_opensearchserverless_security_policy" "encryption" {
  name        = "${var.project}-encryption"
  type        = "encryption"
  description = "AWS-managed key encryption for ${var.project} collection"

  policy = jsonencode({
    AWSOwnedKey = true
    Rules = [{
      Resource     = ["collection/${local.collection_name}"]
      ResourceType = "collection"
    }]
  })
}


# Network Policy

resource "aws_opensearchserverless_security_policy" "network" {
  name        = "${var.project}-network"
  type        = "network"
  description = "Network policy for ${var.project} — public access (dev only)"

  policy = jsonencode([
    {

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
    }
  ])
}


# Collection

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


# Data Access Policy — Read-Only

resource "aws_opensearchserverless_access_policy" "readonly" {
  name        = "${var.project}-aoss-readonly"
  type        = "data"
  description = "Read-only access — can read documents and describe indexes"

  policy = jsonencode([
    {
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
          Permission = [
            "aoss:ReadDocument",
            "aoss:DescribeIndex"
          ]
        }
      ]
    }
  ])
}


# Data Access Policy — Read-Write

resource "aws_opensearchserverless_access_policy" "readwrite" {
  name        = "${var.project}-aoss-readwrite"
  type        = "data"
  description = "Read-write access — full index operations"

  policy = jsonencode([
    {
      Description = "Read-write access"
      Principal   = [aws_iam_role.aoss_readwrite.arn]
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
    }
  ])
}


# DynamoDB — Enrichment Cache

resource "aws_dynamodb_table" "enrichment_cache" {
  name         = "${var.project}-enrichment-cache"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "PK"
  range_key = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Environment = "dev"
    Project     = var.project
  }
}
