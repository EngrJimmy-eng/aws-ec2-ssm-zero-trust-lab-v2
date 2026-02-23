
# Hardened S3 Bucket Setup
# Project: Zero Trust Lab






# Account-level Public Access Block

resource "aws_s3_account_public_access_block" "account_block" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}


# Main Secure Bucket

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "${var.project_name}-secure-bucket"

  

  tags = {
    Name = "${var.project_name}-secure-bucket"
  }
}

resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_sse" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}


# S3 Bucket Policy

resource "aws_s3_bucket_policy" "secure_policy" {
  bucket = aws_s3_bucket.secure_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Allow only EC2 role
      {
        Sid       = "AllowEC2Role"
        Effect    = "Allow"
        Principal = {
  AWS = aws_iam_role.ec2_ssm_role.arn
}
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


# Server Access Logging Bucket

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


# Lifecycle Rule

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





# CloudWatch Alert for Policy Change

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

resource "aws_cloudwatch_metric_alarm" "bucket_policy_alarm" {
  alarm_name          = "s3-bucket-policy-change"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "NumberOfObjects"
  namespace           = "AWS/S3"
  period              = 300
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Alert if bucket policy changes"
  actions_enabled     = true

  # Optional SNS topic to notify:
  # alarm_actions = [aws_sns_topic.security_alerts.arn]
}
