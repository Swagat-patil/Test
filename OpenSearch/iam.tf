data "aws_caller_identity" "current" {}

# IAM Users (service accounts)


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


# IAM Roles


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

resource "aws_iam_role" "lambda_role" {
  name = "${var.project}-lambda-role"

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


# IAM Policies


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

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
