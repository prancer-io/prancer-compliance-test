package rule


#
# PR-AWS-TRF-VPC-001
#

default vpc_subnet_autoip = null

aws_issue["vpc_subnet_autoip"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_subnet"
    lower(resource.properties.map_public_ip_on_launch) == "true"
}

source_path[{"vpc_subnet_autoip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_subnet"
    lower(resource.properties.map_public_ip_on_launch) == "true"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "map_public_ip_on_launch"]
        ],
    }
}

aws_bool_issue["vpc_subnet_autoip"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_subnet"
    resource.properties.map_public_ip_on_launch == true
}

source_path[{"vpc_subnet_autoip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_subnet"
    resource.properties.map_public_ip_on_launch == true

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "map_public_ip_on_launch"]
        ],
    }
}

vpc_subnet_autoip {
    lower(input.resources[i].type) == "aws_subnet"
    not aws_issue["vpc_subnet_autoip"]
    not aws_bool_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip = false {
    aws_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip = false {
    aws_bool_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip_err = "AWS VPC subnets should not allow automatic public IP assignment" {
    aws_issue["vpc_subnet_autoip"]
} else = "AWS VPC subnets should not allow automatic public IP assignment" {
    aws_bool_issue["vpc_subnet_autoip"]
}

vpc_subnet_autoip_metadata := {
    "Policy Code": "PR-AWS-TRF-VPC-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS VPC subnets should not allow automatic public IP assignment",
    "Policy Description": "This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.",
    "Resource Type": "aws_subnet",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html"
}

#
# PR-AWS-TRF-VPC-002
#

default eip_instance_link = null

aws_issue["eip_instance_link"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eip"
    lower(resource.properties.domain) == "vpc"
    not resource.properties.instance
}

source_path[{"eip_instance_link": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eip"
    lower(resource.properties.domain) == "vpc"
    not resource.properties.instance
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "instance"]
        ],
    }
}

aws_issue["eip_instance_link"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eip"
    lower(resource.properties.domain) == "vpc"
    count(resource.properties.instance) == 0
}

source_path[{"eip_instance_link": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eip"
    lower(resource.properties.domain) == "vpc"
    count(resource.properties.instance) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "instance"]
        ],
    }
}

aws_issue["eip_instance_link"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eip"
    lower(resource.properties.domain) == "vpc"
    resource.properties.instance == null
}

source_path[{"eip_instance_link": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eip"
    lower(resource.properties.domain) == "vpc"
    resource.properties.instance == null
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "instance"]
        ],
    }
}

eip_instance_link {
    lower(input.resources[i].type) == "aws_eip"
    not aws_issue["eip_instance_link"]
}

eip_instance_link = false {
    aws_issue["eip_instance_link"]
}

eip_instance_link_err = "Ensure all EIP addresses allocated to a VPC are attached related EC2 instances" {
    aws_issue["eip_instance_link"]
}

eip_instance_link_metadata := {
    "Policy Code": "PR-AWS-TRF-VPC-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure all EIP addresses allocated to a VPC are attached related EC2 instances",
    "Policy Description": "Ensure that a managed Config rule for AWS Elastic IPs (EIPs) attached to EC2 instances launched inside a VPC is created. Config service tracks changes within your AWS resources configuration and saves the recorded data for security and compliance audits",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip"
}


#
# PR-AWS-TRF-VPC-003
#

default vpc_endpoint_manual_acceptance = null

aws_issue["vpc_endpoint_manual_acceptance"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_vpc_endpoint_service"
    lower(resource.properties.acceptance_required) != "true"
}

source_path[{"vpc_endpoint_manual_acceptance": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_vpc_endpoint_service"
    lower(resource.properties.acceptance_required) != "true"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "acceptance_required"]
        ],
    }
}

aws_issue["vpc_endpoint_manual_acceptance"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_vpc_endpoint_service"
    not resource.properties.acceptance_required
}

source_path[{"vpc_endpoint_manual_acceptance": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_vpc_endpoint_service"
    not resource.properties.acceptance_required
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "acceptance_required"]
        ],
    }
}

vpc_endpoint_manual_acceptance {
    lower(input.resources[i].type) == "aws_vpc_endpoint_service"
    not aws_issue["vpc_endpoint_manual_acceptance"]
}

vpc_endpoint_manual_acceptance = false {
    aws_issue["vpc_endpoint_manual_acceptance"]
}

vpc_endpoint_manual_acceptance_err = "Ensure VPC endpoint service is configured for manual acceptance" {
    aws_issue["vpc_endpoint_manual_acceptance"]
}

vpc_endpoint_manual_acceptance_metadata := {
    "Policy Code": "PR-AWS-TRF-VPC-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure VPC endpoint service is configured for manual acceptance",
    "Policy Description": "acceptance_required Indicates whether requests from service consumers to create an endpoint to your service must be accepted, we recommend you to enable this feature",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint_service"
}


#
# PR-AWS-TRF-VPC-006
#

default vpc_policy_not_overly_permissive = null

aws_issue["vpc_policy_not_overly_permissive"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_vpc_endpoint"
    statement := resource.properties.policy.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    contains(lower(statement.Action), "*")
    not statement.Condition
}

aws_issue["vpc_policy_not_overly_permissive"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_vpc_endpoint"
    statement := resource.properties.policy.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    contains(lower(statement.Action[_]), "*")
    not statement.Condition
}

aws_issue["vpc_policy_not_overly_permissive"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_vpc_endpoint"
    statement := resource.properties.policy.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action), "*")
    not statement.Condition
}

aws_issue["vpc_policy_not_overly_permissive"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_vpc_endpoint"
    statement := resource.properties.policy.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    contains(lower(statement.Action[_]), "*")
    not statement.Condition
}

aws_issue["vpc_policy_not_overly_permissive"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_vpc_endpoint"
    statement := resource.properties.policy.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] == "*"
    contains(lower(statement.Action), "*")
    not statement.Condition
}

aws_issue["vpc_policy_not_overly_permissive"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_vpc_endpoint"
    statement := resource.properties.policy.Statement[i]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[_] == "*"
    contains(lower(statement.Action[_]), "*")
    not statement.Condition
}

vpc_policy_not_overly_permissive {
    lower(input.resources[i].type) == "aws_vpc_endpoint"
    not aws_issue["vpc_policy_not_overly_permissive"]
}

vpc_policy_not_overly_permissive = false {
    aws_issue["vpc_policy_not_overly_permissive"]
}

vpc_policy_not_overly_permissive_err = "Ensure AWS VPC endpoint policy is not overly permissive." {
    aws_issue["vpc_policy_not_overly_permissive"]
}

vpc_policy_not_overly_permissive_metadata := {
    "Policy Code": "PR-AWS-TRF-VPC-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS VPC endpoint policy is not overly permissive.",
    "Policy Description": "It identifies VPC endpoints that have a VPC endpoint (VPCE) policy that is overly permissive. When the Principal element value is set to '*' within the access policy, the VPC endpoint allows full access to any IAM user or service within the VPC using credentials from any AWS accounts. It is highly recommended to have the least privileged VPCE policy to protect the data leakage and unauthorized access. For more details: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint#policy"
}
