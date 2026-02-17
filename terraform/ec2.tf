# Get latest Amazon Linux 2 AMI (eu-west-1 safe)
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

}

resource "aws_security_group" "ec2_sg" {
  name   = "ec2-ssm-sg"
  description = "Allow outbound traffic"
  vpc_id = aws_vpc.this.id


  # Zero Trust – no inbound rules

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "ec2_ssm" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = true
subnet_id = aws_subnet.private.id
associate_public_ip_address = false

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project_name}-ec2"
  }
}
