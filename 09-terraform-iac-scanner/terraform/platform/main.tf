# Endon AI platform baseline, in Terraform.
#
# This mirrors the CDK PlatformStack (endon-core) as an idiomatic Terraform module: one
# customer-managed KMS key, the incident and finding DynamoDB tables, and an Object Lock
# evidence bucket — all encrypted, private and rotation-enabled. It is written to *pass*
# endon-tfscan cleanly, so the scanner and the infrastructure it guards tell the same story.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.region
}

locals {
  tags = {
    project    = "endon-ai"
    component  = "platform"
    managed-by = "terraform"
  }
}

# --- Customer-managed key for every platform data store -----------------------------
resource "aws_kms_key" "platform" {
  description         = "Encrypts Endon AI incidents, findings and evidence"
  enable_key_rotation = true
  tags               = local.tags
}

resource "aws_kms_alias" "platform" {
  name          = "alias/endon-platform"
  target_key_id = aws_kms_key.platform.key_id
}

# --- Incident and finding tables ----------------------------------------------------
resource "aws_dynamodb_table" "incidents" {
  name         = "endon-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.platform.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  deletion_protection_enabled = true
  tags                        = local.tags
}

resource "aws_dynamodb_table" "findings" {
  name         = "endon-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.platform.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  deletion_protection_enabled = true
  tags                        = local.tags
}

# --- Immutable evidence bucket (WORM) -----------------------------------------------
resource "aws_s3_bucket" "evidence" {
  bucket              = var.evidence_bucket_name
  object_lock_enabled = true
  tags                = local.tags

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.platform.arn
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90
    }
  }
}
