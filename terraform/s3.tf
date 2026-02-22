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

resource "aws_s3_bucket_policy" "secure_policy" {
  bucket = aws_s3_bucket.secure_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      
      # 🔒 Deny Non-HTTPS Requests
      
      {
        Sid = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.secure_bucket.arn,
          "${aws_s3_bucket.secure_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },

      
      # 🔒 Deny Unencrypted Uploads
      
      {
        Sid = "DenyUnEncryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.secure_bucket.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "AES256"
          }
        }
      },

      
      # ✅ Allow ONLY EC2 IAM Role
      
      {
        Sid = "AllowEC2RoleAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.ec2_ssm_role.arn
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.secure_bucket.arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "deny_delete_objects" {
  bucket = aws_s3_bucket.secure_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "DenyDeleteObjects"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:DeleteObject"
        Resource = "${aws_s3_bucket.secure_bucket.arn}/*"
      }
    ]
  })
}

# Logs Bucket (no ACL, no object_ownership)
resource "aws_s3_bucket" "secure_logs_bucket" {
  bucket = "${var.project_name}-secure-logs"

  tags = {
    Name = "${var.project_name}-secure-logs-bucket"
  }
}

# Enable logging on main bucket
resource "aws_s3_bucket_logging" "bucket_logging" {
  bucket = aws_s3_bucket.secure_bucket.id

  target_bucket = aws_s3_bucket.secure_logs_bucket.id
  target_prefix = "access-logs/"
}
