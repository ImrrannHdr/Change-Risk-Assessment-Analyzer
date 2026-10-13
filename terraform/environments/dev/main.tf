terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "aws-iac-risk-engine"
      Environment = "dev"
      Owner       = "Imran Haider"
      ManagedBy   = "Terraform"
    }
  }
}

module "plan_storage" {
  source = "../../modules/plan-storage"

  project_name = "aws-iac-risk-engine-dev"

  tags = {
    Purpose = "Terraform Plan Analysis Storage"
    Owner   = "Imran"
  }
}


module "analysis_results" {
  source = "../../modules/analysis-results"

  project_name = "aws-iac-risk-engine-dev"

  tags = {
    Purpose = "Risk Analysis Results"
  }
}


module "notifications" {
  source = "../../modules/notifications"

  project_name   = "aws-iac-risk-engine-dev"
  email_endpoint = "saveuniverse2012@gmail.com"

  tags = {
    Purpose = "Terraform Risk Alerts"
  }
}

module "lambda_role" {
  source = "../../modules/lambda-role"

  project_name = "aws-iac-risk-engine-dev"

  plan_bucket_arn            = module.plan_storage.bucket_arn
  analysis_results_table_arn = module.analysis_results.table_arn
  risk_alert_topic_arn       = module.notifications.topic_arn
}


module "lambda" {
  source = "../../modules/lambda"

  function_name = "aws-iac-risk-engine-dev"

  lambda_zip_path = abspath(
    "${path.root}/../../../build/lambda.zip"
  )

  lambda_role_arn = module.lambda_role.role_arn

  analysis_results_table_name = module.analysis_results.table_name
  risk_alert_topic_arn        = module.notifications.topic_arn

  environment = "dev"

  tags = {
    Project     = "aws-iac-risk-engine"
    Environment = "dev"
  }
}


module "step_functions" {
  source = "../../modules/step-functions"

  project_name        = "aws-iac-risk-engine-dev"
  lambda_function_arn = module.lambda.function_arn
  tags                = var.tags
}



module "eventbridge" {
  source = "../../modules/eventbridge"

  project_name      = "aws-iac-risk-engine-dev"
  plan_bucket_name  = module.plan_storage.bucket_name
  state_machine_arn = module.step_functions.state_machine_arn


  tags = {
    Project     = "aws-iac-risk-engine"
    Environment = "dev"
  }
}


module "github_oidc" {
  source = "../../modules/github-oidc"

  project_name = "aws-iac-risk-engine-dev"

  github_repository = "ImrrannHdr/Change-Risk-Assessment-Analyzer"


  plan_bucket_arn = module.plan_storage.bucket_arn

  terraform_state_bucket_arn = "arn:aws:s3:::imran-iac-risk-tfstate-file-2026"

  tags = {
    Project     = "aws-iac-risk-engine"
    Environment = "dev"
  }
}