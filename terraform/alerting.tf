

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = "ndumeleikenna@gmail.com"
}

# 1️⃣ SNS Topic
resource "aws_sns_topic" "security_alerts" {
  name = "security-alerts-topic"
}

# 2️⃣ Email subscription (optional)
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = "ndumeleikenna@gmail.com"
}

# 3️⃣ SMS subscription
resource "aws_sns_topic_subscription" "sms_subscription" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "sms"
  endpoint  = "+2347032951395"  # Your phone number
}
