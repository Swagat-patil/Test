resource "aws_opensearchserverless_access_policy" "readwrite" {
  name = "${var.project}-aoss-readwrite"
  type = "data"

  policy = jsonencode([
    {
      Description = "Read-write OpenSearch access"

      Principal = var.aoss_readwrite_users

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
            "aoss:*"
          ]
        }
      ]
    }
  ])
}
