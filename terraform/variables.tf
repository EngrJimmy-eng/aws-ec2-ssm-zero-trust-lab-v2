variable "project_name" {
  description = "Project name for tagging resources"
  type        = string
  default     = "ec2-zero-trust-logging"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "ami_name" {
  description = "Name of the Amazon Linux 2 AMI (for eu-west-1)"
  type        = string
  default     = "amzn2-ami-hvm-2.0.*-x86_64-gp2"
}
