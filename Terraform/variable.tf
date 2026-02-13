variable "aws_region" {
  default = "us-east-1"
}

variable "project" {
  default = "dev-app"
}

variable "aoss_readonly_users" {
  description = "IAM users with read-only OpenSearch access"
  type        = list(string)
  default     = []
}

variable "aoss_readwrite_users" {
  description = "IAM users with read-write OpenSearch access"
  type        = list(string)
  default     = []
}

