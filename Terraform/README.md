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



