resource "aws_opensearchserverless_access_policy" "readonly" {
  name = "${var.project}-aoss-readonly"
  type = "data"

  policy = jsonencode([
    {
      Description = "Read-only OpenSearch access"

      Principal = var.aoss_readonly_users

      Rules = [
        {
          ResourceType = "collection"
          Resource     = ["collection/${local.collection_name}"]
          Permission   = [
            "aoss:DescribeCollectionItems"
          ]
        },
        {
          ResourceType = "index"
          Resource     = ["index/${local.collection_name}/*"]
          Permission   = [
            "aoss:ReadDocument",
            "aoss:DescribeIndex"
          ]
        }
      ]
    }
  ])
}
