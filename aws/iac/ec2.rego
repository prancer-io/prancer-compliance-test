package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-CFR-EC2-001
#

default ec2_iam_role = null

aws_issue["ec2_iam_role"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.IamInstanceProfile
}

source_path[{"ec2_iam_role": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.IamInstanceProfile
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "IamInstanceProfile"]
        ],
    }
}

aws_issue["ec2_iam_role"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not startswith(lower(resource.Properties.IamInstanceProfile), "arn:")
}

source_path[{"ec2_iam_role": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not startswith(lower(resource.Properties.IamInstanceProfile), "arn:")
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "IamInstanceProfile"]
        ],
    }
}

ec2_iam_role {
    lower(input.Resources[i].Type) == "aws::ec2::instance"
    not aws_issue["ec2_iam_role"]
}

ec2_iam_role = false {
    aws_issue["ec2_iam_role"]
}

ec2_iam_role_err = "AWS EC2 Instance IAM Role not enabled" {
    aws_issue["ec2_iam_role"]
}

ec2_iam_role_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EC2 Instance IAM Role not enabled",
    "Policy Description": "AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-CFR-EC2-002
#

default ec2_no_vpc = null

aws_issue["ec2_no_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.SubnetId
    count([c | resource.Properties.NetworkInterfaces[_].SubnetId; c := 1]) == 0
}

source_path[{"ec2_no_vpc": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.SubnetId
    count([c | resource.Properties.NetworkInterfaces[_].SubnetId; c := 1]) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkInterfaces"]
        ],
    }
}

ec2_no_vpc {
    lower(input.Resources[i].Type) == "aws::ec2::instance"
    not aws_issue["ec2_no_vpc"]
}

ec2_no_vpc = false {
    aws_issue["ec2_no_vpc"]
}

ec2_no_vpc_err = "AWS EC2 instance is not configured with VPC" {
    aws_issue["ec2_no_vpc"]
}

ec2_no_vpc_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EC2 instance is not configured with VPC",
    "Policy Description": "This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-CFR-EC2-003
#

default ec2_public_ip = null

aws_attribute_absence["ec2_public_ip"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    NetworkInterfaces := resource.Properties.NetworkInterfaces[j]
    not has_property(NetworkInterfaces, "AssociatePublicIpAddress")
}

source_path[{"ec2_public_ip": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    NetworkInterfaces := resource.Properties.NetworkInterfaces[j]
    not has_property(NetworkInterfaces, "AssociatePublicIpAddress")
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NetworkInterfaces", j]
        ],
    }
}

aws_issue["ec2_public_ip"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    lower(resource.Properties.NetworkInterfaces[j].AssociatePublicIpAddress) == "true"
    lower(resource.Properties.SecurityGroups[k]) == "default"
}

source_path[{"ec2_public_ip": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    lower(resource.Properties.NetworkInterfaces[j].AssociatePublicIpAddress) == "true"
    lower(resource.Properties.SecurityGroups[k]) == "default"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups", k]
        ],
    }
}

aws_bool_issue["ec2_public_ip"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    resource.Properties.NetworkInterfaces[j].AssociatePublicIpAddress == true
    lower(resource.Properties.SecurityGroups[k]) == "default"
}

source_path[{"ec2_public_ip": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    resource.Properties.NetworkInterfaces[j].AssociatePublicIpAddress == true
    lower(resource.Properties.SecurityGroups[k]) == "default"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups", k]
        ],
    }
}

ec2_public_ip {
    lower(input.Resources[i].Type) == "aws::ec2::instance"
    not aws_issue["ec2_public_ip"]
    not aws_bool_issue["ec2_public_ip"]
    not aws_attribute_absence["ec2_public_ip"]
}

ec2_public_ip = false {
    aws_issue["ec2_public_ip"]
}

ec2_public_ip = false {
    aws_attribute_absence["ec2_public_ip"]
}

ec2_public_ip = false {
    aws_bool_issue["ec2_public_ip"]
}

ec2_public_ip_err = "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access" {
    aws_issue["ec2_public_ip"]
} else = "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access" {
    aws_bool_issue["ec2_public_ip"]
} else = "AWS EC2 instances with Public IP and associated is True by default with Security Groups which have Internet Access" {
    aws_attribute_absence["ec2_public_ip"]
}

ec2_public_ip_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access",
    "Policy Description": "This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-CFR-EC2-004
#

default ec2_ebs_optimized = null

aws_issue["ec2_ebs_optimized"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.EbsOptimized
}

source_path[{"ec2_ebs_optimized": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.EbsOptimized
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EbsOptimized"]
        ],
    }
}

aws_issue["ec2_ebs_optimized"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    lower(resource.Properties.EbsOptimized) == "false"
}

source_path[{"ec2_ebs_optimized": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    lower(resource.Properties.EbsOptimized) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EbsOptimized"]
        ],
    }
}

ec2_ebs_optimized {
    lower(input.Resources[i].Type) == "aws::ec2::instance"
    not aws_issue["ec2_ebs_optimized"]
}

ec2_ebs_optimized = false {
    aws_issue["ec2_ebs_optimized"]
}

ec2_ebs_optimized_err = "Ensure that EC2 instace is EBS Optimized" {
    aws_issue["ec2_ebs_optimized"]
}

ec2_ebs_optimized_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that EC2 instace is EBS Optimized",
    "Policy Description": "Enable EbsOptimized provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal Amazon EBS I/O performance",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-ebsoptimized"
}


#
# PR-AWS-CFR-EC2-005
#

default ec2_monitoring = null

aws_issue["ec2_monitoring"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.Monitoring
}

source_path[{"ec2_monitoring": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.Monitoring
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Monitoring"]
        ],
    }
}

aws_issue["ec2_monitoring"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    lower(resource.Properties.Monitoring) == "false"
}

source_path[{"ec2_monitoring": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    lower(resource.Properties.Monitoring) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Monitoring"]
        ],
    }
}

ec2_monitoring {
    lower(input.Resources[i].Type) == "aws::ec2::instance"
    not aws_issue["ec2_monitoring"]
}

ec2_monitoring = false {
    aws_issue["ec2_monitoring"]
}

ec2_monitoring_err = "Ensure detailed monitoring is enabled for EC2 instances" {
    aws_issue["ec2_monitoring"]
}

ec2_monitoring_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure detailed monitoring is enabled for EC2 instances",
    "Policy Description": "Ensure that detailed monitoring is enabled for your Amazon EC2 instances in order to have enough monitoring data to help you make better decisions on architecting and managing compute resources within your AWS account",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-monitoring"
}

#
# PR-AWS-CFR-EC2-006
#

default ec2_deletion_termination = null

available_true_choices := ["true", true]

aws_issue["ec2_deletion_termination"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    BlockDeviceMappings := resource.Properties.BlockDeviceMappings[_]
    has_property(BlockDeviceMappings.Ebs, "DeleteOnTermination")
    BlockDeviceMappings.Ebs.DeleteOnTermination == available_true_choices[_]
    NetworkInterfaces := resource.Properties.NetworkInterfaces[_]
    has_property(NetworkInterfaces, "DeleteOnTermination")
    NetworkInterfaces.DeleteOnTermination == available_true_choices[_]
}

aws_issue["ec2_deletion_termination"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    BlockDeviceMappings := resource.Properties.BlockDeviceMappings[_]
    has_property(BlockDeviceMappings.Ebs, "DeleteOnTermination")
    BlockDeviceMappings.Ebs.DeleteOnTermination == available_true_choices[_]
    NetworkInterfaces := resource.Properties.NetworkInterfaces[_]
    not has_property(NetworkInterfaces, "DeleteOnTermination")
}

aws_issue["ec2_deletion_termination"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    BlockDeviceMappings := resource.Properties.BlockDeviceMappings[_]
    not has_property(BlockDeviceMappings.Ebs, "DeleteOnTermination")
    NetworkInterfaces := resource.Properties.NetworkInterfaces[_]
    has_property(NetworkInterfaces, "DeleteOnTermination")
    NetworkInterfaces.DeleteOnTermination == available_true_choices[_]
}

aws_issue["ec2_deletion_termination"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    BlockDeviceMappings := resource.Properties.BlockDeviceMappings[_]
    not has_property(BlockDeviceMappings.Ebs, "DeleteOnTermination")
    NetworkInterfaces := resource.Properties.NetworkInterfaces[_]
    not has_property(NetworkInterfaces, "DeleteOnTermination")
}

ec2_deletion_termination {
    lower(input.Resources[i].Type) == "aws::ec2::instance"
    not aws_issue["ec2_deletion_termination"]
}

ec2_deletion_termination = false {
    aws_issue["ec2_deletion_termination"]
}

ec2_deletion_termination_err = "Ensure AWS EC2 EBS and Network components' deletion protection is enabled" {
    aws_issue["ec2_deletion_termination"]
}

ec2_deletion_termination_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS EC2 EBS and Network components' deletion protection is enabled",
    "Policy Description": "This checks if the EBS volumes are configured to be terminated along with the EC2 instance",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-blockdev-template.html#cfn-ec2-blockdev-template-deleteontermination"
}

#
# PR-AWS-CFR-EC2-007
#

default ami_not_infected = null

aws_issue["ami_not_infected"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    contains(lower(resource.Properties.ImageId), "ami-1e542176")
}

ami_not_infected {
    lower(input.Resources[i].Type) == "aws::ec2::instance"
    not aws_issue["ami_not_infected"]
}

ami_not_infected = false {
    aws_issue["ami_not_infected"]
}

ami_not_infected_err = "Ensure Amazon Machine Image (AMI) is not infected with mining malware." {
    aws_issue["ami_not_infected"]
}

ami_not_infected_metadata := {
    "Policy Code": "PR-AWS-CFR-EC2-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Amazon Machine Image (AMI) is not infected with mining malware.",
    "Policy Description": "Ensure that the ID of the AMI is not infected with mining malware",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#aws-properties-ec2-instance--examples"
}