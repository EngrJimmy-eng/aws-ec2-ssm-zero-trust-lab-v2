terraform {
  backend "s3" {
    bucket         = "ikenna-terraform-state"
    key            = "zero-trust-v2/ec2.tfstate"
    region         = "eu-west-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}
