
variable "vpc_cidr" {
  type    = string
  default = "10.248.0.0/20"
}

variable "enable_test_route" {
  description = "True for baseline; false only when generating the proposed deletion plan."
  type        = bool
  default     = true
}

variable "test_destination_cidr" {
  description = "Documentation-only IPv4 destination for safe route update plans."
  type        = string
  default     = "198.51.100.0/24"
}

variable "create_test_eni" {
  description = "Optionally create a disposable, unattached ENI so Stage 3B observes a real dependency."
  type        = bool
  default     = false
}

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "route-impact-isolated-lab-vpc" }
}

resource "aws_subnet" "explicit" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, 0)
  map_public_ip_on_launch = false
  tags                    = { Name = "route-impact-explicit-subnet" }
}

# This subnet has NO explicit route-table association.
# It inherits the VPC's AWS-created main route table.
resource "aws_subnet" "implicit" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, 1)
  map_public_ip_on_launch = false
  tags                    = { Name = "route-impact-implicit-subnet" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "route-impact-lab-igw" }
}

resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.lab.id
  # Routes intentionally managed with separate aws_route resources.
  # Never add inline route blocks here.
  tags = { Name = "route-impact-lab-custom-rt" }
}

resource "aws_route_table_association" "explicit" {
  subnet_id      = aws_subnet.explicit.id
  route_table_id = aws_route_table.lab.id
}

resource "aws_route" "test" {
  count                  = var.enable_test_route ? 1 : 0
  route_table_id         = aws_route_table.lab.id
  destination_cidr_block = var.test_destination_cidr
  gateway_id             = aws_internet_gateway.lab.id
}

# Optional read-only impact discovery demonstration: no compute workloads.
resource "aws_security_group" "lab_eni" {
  count       = var.create_test_eni ? 1 : 0
  name_prefix = "route-impact-lab-eni-"
  description = "Isolated test ENI security group"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "route-impact-lab-eni-sg" }
}

resource "aws_network_interface" "lab" {
  count           = var.create_test_eni ? 1 : 0
  subnet_id       = aws_subnet.explicit.id
  security_groups = [aws_security_group.lab_eni[0].id]
  description     = "Unattached ENI for route dependency discovery"
  tags            = { Name = "route-impact-lab-test-eni" }
}

output "account_test_vpc_id" { value = aws_vpc.lab.id }
output "custom_route_table_id" { value = aws_route_table.lab.id }
output "explicit_subnet_id" { value = aws_subnet.explicit.id }
output "implicit_subnet_id" { value = aws_subnet.implicit.id }
output "test_route_destination" { value = var.enable_test_route ? var.test_destination_cidr : null }
output "test_eni_id" { value = var.create_test_eni ? aws_network_interface.lab[0].id : null }



/*
variable "enable_sg_test" {
  description = "Enable disposable SG lifecycle test resources"
  type        = bool
  default     = true
}

variable "enable_sg_test_ingress" {
  description = "Control lifecycle test ingress rule"
  type        = bool
  default     = true
}

variable "sg_test_name" {
  description = "Name of disposable test security group"
  type        = string
  default     = "iac-risk-sg-lifecycle-test-v2"
}

variable "sg_test_vpc_id" {
  description = "Existing non-production VPC ID"
  type        = string
  default     = "vpc-0c34a550ddff39e56"
}

resource "aws_security_group" "lifecycle_test_stage2d" {
  count = var.enable_sg_test ? 1 : 0

  name        = var.sg_test_name
  description = "Disposable SG for Terraform risk assessment testing"
  vpc_id      = var.sg_test_vpc_id

  tags = {
    Purpose   = "Terraform-Risk-Testing"
    ManagedBy = "Terraform"
  }
}

resource "aws_vpc_security_group_ingress_rule" "lifecycle_test_https" {
  count = var.enable_sg_test && var.enable_sg_test_ingress ? 1 : 0

  security_group_id = aws_security_group.lifecycle_test_stage2d[0].id

  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443
  cidr_ipv4   = "10.0.0.0/16"

  description = "HTTPS rule for SG replacement assessment"
}





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
  type    = string
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



resource "aws_security_group" "lifecycle_test2" {
  name_prefix = "risk-analyzer-lifecycle-test-"
  description = "Terraform Risk Analyzer lifecycle creation test"

  vpc_id = data.aws_vpc.selected.id

  tags = {
    Name        = "risk-analyzer-lifecycle-test"
    Environment = "dev"
    Purpose     = "LifecycleAnalysisTesting"
  }
}

*/


