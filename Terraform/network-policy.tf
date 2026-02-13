resource "aws_opensearchserverless_security_policy" "network" {
  name = "${var.project}-network"
  type = "network"

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
