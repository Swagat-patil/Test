# OpenSearch Serverless Infrastructure

This Terraform configuration provisions using:

- ✅ OpenSearch Serverless (AOSS)
- ✅ IAM-based authentication
- ✅ Read-only and Read-write roles
- ✅ DynamoDB table for event storage
- ✅ IAM glue layer for future Lambda integration

---

# 🏗 Architecture Overview

OpenSearch Serverless uses **IAM-based authentication only**.

Access is controlled via:
- OpenSearch Serverless **Data Access Policies**
- IAM roles (Read-only / Read-write)

---

# 📦 What This Terraform Creates

## 1️⃣ OpenSearch Serverless

- Collection
- Encryption Policy
- Network Policy
- Data Access Policy
- Dashboard endpoint
- Collection endpoint

### IAM Roles:
- `dev-app-aoss-readonly`
- `dev-app-aoss-readwrite`

---

## 2️⃣ DynamoDB

Table:

---------------
Deployemnt steps
1.terraform init
2.terraform plan
3.terraform apply

After apply, Terraform outputs:
-OpenSearch dashboard URL
-OpenSearch endpoint
-DynamoDB table name
-IAM role ARNs

output
aoss_readonly_role_arn = "arn:aws:iam::782428716412:role/dev-app-aoss-readonly"

aoss_readwrite_role_arn = "arn:aws:iam::782428716412:role/dev-app-aoss-readwrite"

dynamodb_table_name = "enrichment_cache"

opensearch_dashboard_url = "https://szf4fp4fonovhgvcdv5b.us-east-1.aoss.amazonaws.com/_dashboards"        
opensearch_endpoint = "https://szf4fp4fonovhgvcdv5b.us-east-1.aoss.amazonaws.com"

