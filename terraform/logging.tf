resource "aws_s3_bucket" "log_archive" {
  bucket = "ikenna-zero-trust-log-archive"

  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.log_archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kinesis_firehose_delivery_stream" "cw_to_s3" {
  name        = "cw-to-s3-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn           = aws_iam_role.firehose_role.arn
    bucket_arn         = aws_s3_bucket.log_archive.arn
    buffering_size     = 1
    buffering_interval = 60
  }
}

data "aws_cloudwatch_log_group" "ssm_logs" {
  name = "/zero-trust-lab/ssm-logs"
}

resource "aws_cloudwatch_log_subscription_filter" "ssm_to_firehose" {
  name            = "ssm-logs-to-firehose"
  log_group_name  = data.aws_cloudwatch_log_group.ssm_logs.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cw_to_s3.arn
  role_arn        = aws_iam_role.cw_logs_role.arn
}
