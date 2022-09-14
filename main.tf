terraform {
  backend "s3" {
    bucket = "terraform-statev2"
    key    = "terraform.tfstate"
    region = "eu-central-1"
}
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
}

provider "aws" {
  region = "eu-central-1"
}
