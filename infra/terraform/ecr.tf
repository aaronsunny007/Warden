# Optional image registry for the Warden images. Storage cost only; a lifecycle policy prunes all
# but the most recent few tags so it stays near-free.

locals {
  images = var.create_ecr ? toset(["node", "python", "dashboard"]) : toset([])
}

resource "aws_ecr_repository" "warden" {
  for_each             = local.images
  name                 = "${var.name_prefix}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "warden" {
  for_each   = aws_ecr_repository.warden
  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep only the 5 most recent images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 5 }
      action       = { type = "expire" }
    }]
  })
}
