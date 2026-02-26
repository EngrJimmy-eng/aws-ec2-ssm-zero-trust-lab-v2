resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.project_name}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_encryption" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_block" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail_versioning" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },

      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail_logs" {
  name              = "/aws/cloudtrail/zero-trust"
  retention_in_days = 1
}

resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "RootLoginDetected"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.eventName = \"ConsoleLogin\" }"

  metric_transformation {
    name      = "RootLogin"
    namespace = "ZeroTrustLab"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "stop_logging" {
  name           = "CloudTrailStopped"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs.name
  pattern        = "{ $.eventName = StopLogging }"

  metric_transformation {
    name      = "CloudTrailStopped"
    namespace = "ZeroTrustLab"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "iam_escalation" {
  name           = "IAMPrivilegeEscalation"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs.name
  pattern        = "{ ($.eventName = AttachUserPolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = PutRolePolicy) }"

  metric_transformation {
    name      = "IAMPrivilegeEscalation"
    namespace = "ZeroTrustLab"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "s3_public_policy" {
  name           = "S3PublicPolicyChange"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs.name
  pattern        = "{ $.eventName = PutBucketPolicy }"

  metric_transformation {
    name      = "S3PublicPolicyChange"
    namespace = "ZeroTrustLab"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_alarm" {
  alarm_name          = "SecurityAlert"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootLogin"
  namespace           = "ZeroTrustLab"
  period              = 20
  statistic           = "Sum"
  threshold           = 1

  alarm_actions = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "bucket_policy_change" {
  name           = "s3-bucket-policy-change"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs.name
  pattern        = "{ ($.eventName = PutBucketPolicy) }"

  metric_transformation {
    name      = "BucketPolicyChange"
    namespace = "ZeroTrustLab"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "bucket_policy_alarm" {
  alarm_name          = "s3-bucket-policy-change"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "BucketPolicyChange"
  namespace           = "ZeroTrustLab"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Triggered when S3 bucket policy is changed"

  depends_on = [
    aws_cloudwatch_log_metric_filter.bucket_policy_change
  ]
}



# Get the current AWS account
data "aws_caller_identity" "current" {}








# Lifecycle: archive logs to Glacier after 90 days, delete after 365 days
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_lifecycle" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "ArchiveOldLogs"
    status = "Enabled"

    filter {
      prefix = ""  # applies to all objects
    }

    expiration {
      days = 30
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "iam_privilege_escalation" {
  name           = "IAMPrivilegeEscalation"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs.name
  pattern        = "{ ($.eventName = AttachUserPolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = PutRolePolicy) }"

  metric_transformation {
    name      = "IAMPrivilegeEscalation"
    namespace = "ZeroTrustLab"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "failed_console_login" {
  name           = "FailedConsoleLogin"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs.name
  pattern        = "{ $.eventName = \"ConsoleLogin\" && $.errorMessage = \"Failed authentication\" }"

  metric_transformation {
    name      = "FailedLogin"
    namespace = "ZeroTrustLab"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "root_api_calls" {
  name           = "RootAPICalls"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs.name
  pattern        = "{ $.userIdentity.type = \"Root\" }"

  metric_transformation {
    name      = "RootAPICall"
    namespace = "ZeroTrustLab"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "sg_changes" {
  name           = "SecurityGroupChanges"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_logs.name
  pattern        = "{ ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"AuthorizeSecurityGroupEgress\") || ($.eventName = \"RevokeSecurityGroupIngress\") || ($.eventName = \"RevokeSecurityGroupEgress\") }"

  metric_transformation {
    name      = "SecurityGroupChange"
    namespace = "ZeroTrustLab"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_escalation_alarm" {
  alarm_name          = "IAMPrivilegeEscalationAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPrivilegeEscalation"
  namespace           = "ZeroTrustLab"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
}












