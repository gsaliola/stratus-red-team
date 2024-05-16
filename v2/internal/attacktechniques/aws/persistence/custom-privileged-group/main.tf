terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.71.0"
    }
  }

}

provider "aws" {
  skip_region_validation      = true
  skip_credentials_validation = true
  skip_get_ec2_platforms      = true
}


locals {
  resource_prefix = "stratus-red-team-login-profile"
}

resource "aws_iam_user" "legit-user" {
  name          = "${local.resource_prefix}-user"
  force_destroy = true
}

resource "aws_iam_group" "group1" {
  name = "group1"
}

resource "aws_iam_user_group_membership" "membership" {
  user = aws_iam_user.legit-user.name

  groups = [
    aws_iam_group.group1.name,
  ]
}

output "group_name" {
  value = aws_iam_group.group1.name
}

output "user_name" {
  value = aws_iam_user.legit-user.name
}
