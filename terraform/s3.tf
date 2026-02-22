# Account-Level S3 Public Access Block


resource "aws_s3_account_public_access_block" "account_block" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}


# Secure S3 Bucket


resource "aws_s3_bucket" "secure_bucket" {
  bucket = "${var.project_name}-secure-bucket"
}


# Versioning


resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.secure_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}


# Server-Side Encryption


resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}


# Bucket-Level Public Access Block


resource "aws_s3_bucket_public_access_block" "bucket_block" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
