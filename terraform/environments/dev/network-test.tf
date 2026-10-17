resource "aws_security_group" "risk_test" {
  name_prefix = "risk-analyzer-test-"
  description = "Test security group for Terraform Risk Analyzer"

  vpc_id = data.aws_vpc.selected.id

  tags = {
    Name        = "risk-analyzer-network-test"
    Environment = "dev"
    Purpose     = "RiskAnalyzerTesting"
  }
}


data "aws_vpc" "selected" {
  id = "vpc-0c34a550ddff39e56"
}


resource "aws_vpc_security_group_ingress_rule" "test_https" {
  security_group_id = aws_security_group.risk_test.id

  description = "Risk analyzer test HTTPS access"

  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443

  cidr_ipv4 = "0.0.0.0/0"

  tags = {
    Name = "risk-test-https"
  }
}



resource "aws_vpc_security_group_ingress_rule" "blast_radius_test" {
  security_group_id = "sg-0384eb54753e68e8b"

  description = "Terraform Risk Analyzer blast-radius test"

  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443

  cidr_ipv4 = "0.0.0.0/0"

  tags = {
    Name        = "blast-radius-test"
    Environment = "dev"
  }
}
