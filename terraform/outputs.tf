output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.this.id
}

output "subnet_id" {
  description = "Public subnet ID"
  value       = aws_subnet.public.id
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.ec2_ssm.id
}

output "instance_public_ip" {
  description = "EC2 public IP"
  value       = aws_instance.this.public_ip_address
}

output "instance_profile_arn" {
  description = "EC2 IAM instance profile ARN"
  value       = aws_iam_instance_profile.this.arn
}
