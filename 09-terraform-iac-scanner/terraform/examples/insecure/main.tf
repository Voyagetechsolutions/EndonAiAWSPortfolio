# A deliberately insecure stack — the scanner's target. Every resource here trips at least
# one control. Do NOT apply this; it exists so `endon-tfscan` can be shown catching real,
# planted misconfigurations. Regenerate the committed plan with:
#   terraform init && terraform plan -out plan.out && terraform show -json plan.out \
#     > ../../plans/insecure.plan.json

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

# TF-S3-001 (public ACL), TF-S3-002 (no encryption), TF-S3-003 (no versioning)
resource "aws_s3_bucket" "public" {
  bucket = "acme-public-exports"
  acl    = "public-read"

  versioning {
    enabled = false
  }
}

# TF-S3-001 — Block Public Access neutralised
resource "aws_s3_bucket_public_access_block" "weak" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# TF-EC2-001 (SSH open to the world) and TF-EC2-002 (8080 open to the world)
resource "aws_security_group" "open" {
  name = "acme-open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# TF-EC2-003 — IMDSv1 still allowed (SSRF can steal instance credentials)
resource "aws_instance" "legacy" {
  ami           = "ami-0abcdef"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens   = "optional"
    http_endpoint = "enabled"
  }
}

# TF-EBS-001 — unencrypted volume
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# TF-RDS-001 (unencrypted) and TF-RDS-002 (publicly accessible)
resource "aws_db_instance" "db" {
  identifier          = "acme-db"
  engine              = "postgres"
  storage_encrypted   = false
  publicly_accessible = true
}

# TF-IAM-001 — administrator-equivalent policy
resource "aws_iam_policy" "admin" {
  name = "acme-admin"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

# TF-IAM-002 — unscoped iam:PassRole (a privilege-escalation path)
resource "aws_iam_policy" "passrole" {
  name = "acme-passrole"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "lambda:CreateFunction"]
      Resource = "*"
    }]
  })
}

# TF-KMS-001 — key rotation disabled
resource "aws_kms_key" "key" {
  description         = "acme data key"
  enable_key_rotation = false
}

# TF-LOG-001 — single-region, unencrypted trail
resource "aws_cloudtrail" "trail" {
  name                  = "acme-trail"
  is_multi_region_trail = false
}
