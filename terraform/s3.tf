##############################
# Hardened S3 Bucket Setup
# Project: Zero Trust Lab
##############################

variable "project_name" {
  default = "ec2-zero-trust-logging"
}

variable "ec2_role_arn" {
  description = "IAM Role ARN allowed to access the bucket"
}

#################################
# Account-level Public Access Block
#################################
resource "aws_s3_account_public_access_block" "account_block" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

######################
# Main Secure Bucket
######################
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "${var.project_name}-secure-bucket"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Name = "${var.project_name}-secure-bucket"
  }
}

#########################
# S3 Bucket Policy
#########################
resource "aws_s3_bucket_policy" "secure_policy" {
  bucket = aws_s3_bucket.secure_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow only EC2 role
      {
        Sid       = "AllowEC2Role"
        Effect    = "Allow"
        Principal = { AWS = var.ec2_role_arn }
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.secure_bucket.arn,
          "${aws_s3_bucket.secure_bucket.arn}/*"
        ]
      },

      # Deny non-HTTPS
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.secure_bucket.arn,
          "${aws_s3_bucket.secure_bucket.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },

      # Deny unencrypted uploads
      {
        Sid       = "DenyUnEncryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.secure_bucket.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "AES256"
          }
        }
      },

      # Deny deletion of objects
      {
        Sid       = "DenyDeleteObjects"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteObject"
        Resource  = "${aws_s3_bucket.secure_bucket.arn}/*"
      }
    ]
  })
}

##################################
# Server Access Logging Bucket
##################################
resource "aws_s3_bucket" "secure_logs_bucket" {
  bucket = "${var.project_name}-secure-logs"

  tags = {
    Name = "${var.project_name}-secure-logs-bucket"
  }
}

resource "aws_s3_bucket_logging" "bucket_logging" {
  bucket        = aws_s3_bucket.secure_bucket.id
  target_bucket = aws_s3_bucket.secure_logs_bucket.id
  target_prefix = "access-logs/"
}

######################
# Lifecycle Rule
######################
resource "aws_s3_bucket_lifecycle_configuration" "secure_lifecycle" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    id     = "ArchiveOldObjects"
    status = "Enabled"

    filter { prefix = "" }

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

#################################
# CloudTrail Data Event for S3
#################################
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.secure_logs_bucket.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = [
        "${aws_s3_bucket.secure_bucket.arn}/"
      ]
    }
  }
}

#################################
# CloudWatch Alert for Policy Change
#################################
resource "aws_cloudwatch_log_metric_filter" "bucket_policy_change" {
  name           = "BucketPolicyChange"
  log_group_name = "/aws/cloudtrail/${var.project_name}-cloudtrail-logs"

  pattern = "{ ($.eventName = PutBucketPolicy) || ($.eventName = DeleteBucketPolicy) }"

  metric_transformation {
    name      = "BucketPolicyChange"
    namespace = "S3Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "bucket_policy_alarm" {
  alarm_name          = "${var.project_name}-bucket-policy-change-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.bucket_policy_change.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.bucket_policy_change.metric_transformation[0].namespace
  period              = 60
  statistic           = "Sum"
  threshold           = 1

  alarm_description = "Alarm if S3 bucket policy is changed."
  actions_enabled   = true
  alarm_actions     = [aws_sns_topic.secure_alerts.arn]
}
