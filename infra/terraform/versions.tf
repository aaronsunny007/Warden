terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      project   = "warden"
      managedby = "terraform"
      cost      = "lab"
    }
  }
}

# Budgets and billing metrics live in us-east-1 regardless of the working region.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags {
    tags = {
      project   = "warden"
      managedby = "terraform"
    }
  }
}
