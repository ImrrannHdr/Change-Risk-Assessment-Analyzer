terraform {
  backend "s3" {
    bucket       = "imran-iac-risk-tfstate-file-2026"
    key          = "aws-iac-risk-engine/dev/terraform.tfstate"
    region       = "ap-southeast-2"
    encrypt      = true
    use_lockfile = true
  }
}

