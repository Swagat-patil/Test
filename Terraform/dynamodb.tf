resource "aws_dynamodb_table" "enrichment_cache" {
  name         = "enrichment_cache"
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
    enabled = false
  }

  tags = {
    Environment = "dev"
    Project     = var.project
  }
}
