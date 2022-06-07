package rule


#
# PR-AWS-TRF-EC2-001
#

default ec2_iam_role = null

aws_attribute_absence["ec2_iam_role"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    not resource.properties.iam_instance_profile
}

source_path[{"ec2_iam_role": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    not resource.properties.iam_instance_profile

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "iam_instance_profile"]
        ],
    }
}

aws_issue["ec2_iam_role"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    count(resource.properties.iam_instance_profile) == 0
}

source_path[{"ec2_iam_role": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    count(resource.properties.iam_instance_profile) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "iam_instance_profile"]
        ],
    }
}

ec2_iam_role {
    lower(input.resources[i].type) == "aws_instance"
    not aws_issue["ec2_iam_role"]
    not aws_attribute_absence["ec2_iam_role"]
}

ec2_iam_role = false {
    aws_issue["ec2_iam_role"]
}

ec2_iam_role = false {
    aws_attribute_absence["ec2_iam_role"]
}

ec2_iam_role_err = "AWS EC2 Instance IAM Role not enabled" {
    aws_issue["ec2_iam_role"]
} else = "EC2 instance attribute iam_instance_profile missing in the resource" {
    aws_attribute_absence["ec2_iam_role"]
}

ec2_iam_role_metadata := {
    "Policy Code": "PR-AWS-TRF-EC2-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS EC2 Instance IAM Role not enabled",
    "Policy Description": "AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.",
    "Resource Type": "aws_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-TRF-EC2-002
#

default ec2_no_vpc = null

aws_issue["ec2_no_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    not resource.properties.subnet_id
    network_interface := resource.properties.network_interface[j]
    count([c | network_interface.subnet_id; c := 1]) == 0
}

source_path[{"ec2_no_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    not resource.properties.subnet_id
    network_interface := resource.properties.network_interface[j]
    count([c | network_interface.subnet_id; c := 1]) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_interface", j, "subnet_id"]
        ],
    }
}

aws_issue["ec2_no_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    count(resource.properties.subnet_id) == 0
    network_interface := resource.properties.network_interface[j]
    count([c | network_interface.subnet_id; c := 1]) == 0
}

source_path[{"ec2_no_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    count(resource.properties.subnet_id) == 0
    network_interface := resource.properties.network_interface[j]
    count([c | network_interface.subnet_id; c := 1]) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_interface", j, "subnet_id"]
        ],
    }
}

aws_issue["ec2_no_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    resource.properties.subnet_id == null
    network_interface := resource.properties.network_interface[j]
    count([c | network_interface.subnet_id; c := 1]) == 0
}

source_path[{"ec2_no_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    resource.properties.subnet_id == null
    network_interface := resource.properties.network_interface[j]
    count([c | network_interface.subnet_id; c := 1]) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "network_interface", j, "subnet_id"]
        ],
    }
}

ec2_no_vpc {
    lower(input.resources[i].type) == "aws_instance"
    not aws_issue["ec2_no_vpc"]
}

ec2_no_vpc = false {
    aws_issue["ec2_no_vpc"]
}

ec2_no_vpc_err = "AWS EC2 instance is not configured with VPC" {
    aws_issue["ec2_no_vpc"]
}

ec2_no_vpc_metadata := {
    "Policy Code": "PR-AWS-TRF-EC2-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS EC2 instance is not configured with VPC",
    "Policy Description": "This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-TRF-EC2-003
#

default ec2_public_ip = null

aws_issue["ec2_public_ip"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    lower(resource.properties.associate_public_ip_address) == "true"
    lower(resource.properties.security_groups[_]) == "default"
}

source_path[{"ec2_public_ip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    lower(resource.properties.associate_public_ip_address) == "true"
    lower(resource.properties.security_groups[_]) == "default"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "associate_public_ip_address"]
        ],
    }
}

aws_issue["ec2_public_ip"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    lower(resource.properties.associate_public_ip_address) == "true"
    lower(resource.properties.vpc_security_group_ids[j]) == "default"
}

source_path[{"ec2_public_ip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    lower(resource.properties.associate_public_ip_address) == "true"
    lower(resource.properties.vpc_security_group_ids[j]) == "default"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "associate_public_ip_address"]
        ],
    }
}

aws_bool_issue["ec2_public_ip"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    resource.properties.associate_public_ip_address == true
    lower(resource.properties.security_groups[_]) == "default"
}

source_path[{"ec2_public_ip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    resource.properties.associate_public_ip_address == true
    lower(resource.properties.security_groups[_]) == "default"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "associate_public_ip_address"]
        ],
    }
}

aws_bool_issue["ec2_public_ip"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    resource.properties.associate_public_ip_address == true
    lower(resource.properties.vpc_security_group_ids[j]) == "default"
}

source_path[{"ec2_public_ip": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    resource.properties.associate_public_ip_address == true
    lower(resource.properties.vpc_security_group_ids[j]) == "default"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "associate_public_ip_address"]
        ],
    }
}

ec2_public_ip {
    lower(input.resources[i].type) == "aws_instance"
    not aws_issue["ec2_public_ip"]
    not aws_bool_issue["ec2_public_ip"]
}

ec2_public_ip = false {
    aws_issue["ec2_public_ip"]
}

ec2_public_ip = false {
    aws_bool_issue["ec2_public_ip"]
}

ec2_public_ip_err = "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access" {
    aws_issue["ec2_public_ip"]
} else = "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access" {
    aws_bool_issue["ec2_public_ip"]
}

ec2_public_ip_metadata := {
    "Policy Code": "PR-AWS-TRF-EC2-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access",
    "Policy Description": "This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-TRF-EC2-004
#

default ec2_ebs_optimized = null

aws_issue["ec2_ebs_optimized"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    not resource.properties.ebs_optimized
}

source_path[{"ec2_ebs_optimized": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    not resource.properties.ebs_optimized
    metadata := {
        "resource_path": [
            ["resources", i, ".properties", "ebs_optimized"]
        ],
    }
}

aws_issue["ec2_ebs_optimized"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    lower(resource.properties.ebs_optimized) == "false"
}

source_path[{"ec2_ebs_optimized": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    lower(resource.properties.ebs_optimized) == "false"
    metadata := {
        "resource_path": [
            ["resources", i, ".properties", "ebs_optimized"]
        ],
    }
}

ec2_ebs_optimized {
    lower(input.resources[i].type) == "aws_instance"
    not aws_issue["ec2_ebs_optimized"]
}

ec2_ebs_optimized = false {
    aws_issue["ec2_ebs_optimized"]
}

ec2_ebs_optimized_err = "Ensure that EC2 instace is EBS Optimized" {
    aws_issue["ec2_ebs_optimized"]
}

ec2_ebs_optimized_metadata := {
    "Policy Code": "PR-AWS-TRF-EC2-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that EC2 instace is EBS Optimized",
    "Policy Description": "Enable ebs_optimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance"
}


#
# PR-AWS-TRF-EC2-005
#

default ec2_monitoring = null

aws_issue["ec2_monitoring"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    not resource.properties.monitoring
}

source_path[{"ec2_monitoring": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    not resource.properties.monitoring
    metadata := {
        "resource_path": [
            ["resources", i, ".properties", "monitoring"]
        ],
    }
}

aws_issue["ec2_monitoring"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    lower(resource.properties.monitoring) == "false"
}

source_path[{"ec2_monitoring": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    lower(resource.properties.monitoring) == "false"
    metadata := {
        "resource_path": [
            ["resources", i, ".properties", "monitoring"]
        ],
    }
}

ec2_monitoring {
    lower(input.resources[i].type) == "aws_instance"
    not aws_issue["ec2_monitoring"]
}

ec2_monitoring = false {
    aws_issue["ec2_monitoring"]
}

ec2_monitoring_err = "Ensure detailed monitoring is enabled for EC2 instances" {
    aws_issue["ec2_monitoring"]
}

ec2_monitoring_metadata := {
    "Policy Code": "PR-AWS-TRF-EC2-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure detailed monitoring is enabled for EC2 instances",
    "Policy Description": "Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance"
}

#
# PR-AWS-TRF-EC2-006
#

available_true_choices := ["true", true]

default ec2_deletion_termination = null

aws_issue["ec2_deletion_termination"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    ebs_block_device := resource.properties.ebs_block_device[_]
    has_property(ebs_block_device, "delete_on_termination")
    ebs_block_device.delete_on_termination == available_true_choices[_]
    network_interface := resource.properties.network_interface[_]
    has_property(network_interface, "delete_on_termination")
    network_interface.delete_on_termination == available_true_choices[_]
}

aws_issue["ec2_deletion_termination"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    ebs_block_device := resource.properties.ebs_block_device[_]
    has_property(ebs_block_device, "delete_on_termination")
    ebs_block_device.delete_on_termination == available_true_choices[_]
    network_interface := resource.properties.network_interface[_]
    not has_property(network_interface, "delete_on_termination")
}

aws_issue["ec2_deletion_termination"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    ebs_block_device := resource.properties.ebs_block_device[_]
    not has_property(ebs_block_device, "delete_on_termination")
    network_interface := resource.properties.network_interface[_]
    has_property(network_interface, "delete_on_termination")
    network_interface.delete_on_termination == available_true_choices[_]
}

aws_issue["ec2_deletion_termination"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    ebs_block_device := resource.properties.ebs_block_device[_]
    not has_property(ebs_block_device, "delete_on_termination")
    network_interface := resource.properties.network_interface[_]
    not has_property(network_interface, "delete_on_termination")
}

ec2_deletion_termination {
    lower(input.resources[i].type) == "aws_instance"
    not aws_issue["ec2_deletion_termination"]
}

ec2_deletion_termination = false {
    aws_issue["ec2_deletion_termination"]
}

ec2_deletion_termination_err = "Ensure AWS EC2 EBS and Network components' deletion protection is enabled" {
    aws_issue["ec2_deletion_termination"]
}

ec2_deletion_termination_metadata := {
    "Policy Code": "PR-AWS-TRF-EC2-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS EC2 EBS and Network components' deletion protection is enabled",
    "Policy Description": "This checks if the EBS volumes are configured to be terminated along with the EC2 instance",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance"
}

#
# PR-AWS-TRF-EC2-007
#

default ami_not_infected = null

aws_issue["ami_not_infected"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    contains(lower(resource.properties.ami), "ami-1e542176")
}

ami_not_infected {
    lower(input.resources[i].type) == "aws_instance"
    not aws_issue["ami_not_infected"]
}

ami_not_infected = false {
    aws_issue["ami_not_infected"]
}

ami_not_infected_err = "Ensure Amazon Machine Image (AMI) is not infected with mining malware." {
    aws_issue["ami_not_infected"]
}

ami_not_infected_metadata := {
    "Policy Code": "PR-AWS-TRF-EC2-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Amazon Machine Image (AMI) is not infected with mining malware.",
    "Policy Description": "Ensure that the ID of the AMI is not infected with mining malware",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance"
}