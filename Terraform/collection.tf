resource "aws_opensearchserverless_collection" "this" {
  name = local.collection_name
  type = "SEARCH"

  tags = {
    Project = var.project
  }
}
