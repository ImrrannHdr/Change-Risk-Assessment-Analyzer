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



resource "aws_vpc_security_group_ingress_rule" "risk_test_ssh2" {
  security_group_id = "sg-05f740035e7fc92f2"

  ip_protocol = "tcp"
  from_port   = 22
  to_port     = 22
  cidr_ipv4   = "0.0.0.0/0"

  description = "Terraform risk analyzer test - plan only"
}





variable "test_security_group_id" {
  type = string
  default = "sg-05f740035e7fc92f2"
}

resource "aws_vpc_security_group_ingress_rule" "risk_test_ssh" {
  security_group_id = var.test_security_group_id

  ip_protocol = "icmp"
  from_port   = 8
  to_port     = -1
  cidr_ipv4   = "10.0.0.0/16"

  description = "Risk analyzer plan-only test"
}




data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_subnets" "test" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.selected.id]
  }
}

resource "aws_instance" "planned_app" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.micro"

  subnet_id = sort(data.aws_subnets.test.ids)[0]

  vpc_security_group_ids = [
    aws_security_group.risk_test.id
  ]

  tags = {
    Name        = "risk-analyzer-planned-ec2"
    Environment = "dev"
    Purpose     = "PlannedDependencyTesting"
  }
}


