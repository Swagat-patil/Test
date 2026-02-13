resource "aws_opensearchserverless_access_policy" "data_access" {
  name = "${var.project}-data-access"
  type = "data"

  policy = jsonencode([{
    Description = "DEV OpenSearch access"
    Principal = [
      "arn:aws:iam::782428716412:user/rahul",
      aws_iam_role.aoss_readonly.arn,
      aws_iam_role.aoss_readwrite.arn
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
        Permission   = ["aoss:*"]
      }
    ]
  }])
}
