# Vulnerable Terraform - Multiple security issues

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_s3_bucket" "data" {
  bucket = "my-sensitive-data"
  acl    = "public-read-write"
}

resource "aws_security_group" "web" {
  name = "allow-all"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  identifier          = "prod-db"
  engine              = "mysql"
  instance_class      = "db.t3.medium"
  publicly_accessible = true
  storage_encrypted   = false
  backup_retention_period = 0
  password            = "MyDbP@ssw0rd!"
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_iam_role_policy" "admin" {
  name = "admin-policy"
  role = aws_iam_role.admin.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_lambda_function" "processor" {
  function_name = "data-processor"
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  role          = aws_iam_role.lambda.arn
  filename      = "lambda.zip"
}

resource "aws_kms_key" "main" {
  description         = "Main encryption key"
  enable_key_rotation = false
}

resource "aws_sns_topic" "alerts" {
  name = "alert-topic"
}

resource "aws_sqs_queue" "jobs" {
  name = "job-queue"
}

resource "aws_lb" "web" {
  name               = "web-lb"
  internal           = false
  load_balancer_type = "application"
}

resource "aws_default_vpc" "default" {
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled = true

  origin {
    domain_name = "example.com"
    origin_id   = "myOrigin"
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "myOrigin"

    viewer_protocol_policy = "allow-all"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
