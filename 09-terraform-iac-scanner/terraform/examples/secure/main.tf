# The hardened counterpart to ../insecure — every control passes. `endon-tfscan` reports no
# findings on this plan, which is how the benchmark proves the scanner does not cry wolf.
#   terraform plan -out plan.out && terraform show -json plan.out > ../../plans/secure.plan.json

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_kms_key" "key" {
  description         = "acme data key"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "data" {
  bucket = "acme-private-data"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.key.arn
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "web" {
  name = "acme-web"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_instance" "app" {
  ami           = "ami-0abcdef"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.key.arn
}

resource "aws_db_instance" "db" {
  identifier          = "acme-db"
  engine              = "postgres"
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.key.arn
  publicly_accessible = false
}

resource "aws_iam_policy" "scoped" {
  name = "acme-scoped"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::acme-private-data/*"
    }]
  })
}

resource "aws_cloudtrail" "trail" {
  name                  = "acme-trail"
  is_multi_region_trail = true
  kms_key_id            = aws_kms_key.key.arn
}
