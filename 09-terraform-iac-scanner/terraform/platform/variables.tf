variable "region" {
  description = "AWS region for the Endon platform baseline."
  type        = string
  default     = "us-east-1"
}

variable "evidence_bucket_name" {
  description = "Globally-unique name for the Object Lock evidence bucket."
  type        = string
}
