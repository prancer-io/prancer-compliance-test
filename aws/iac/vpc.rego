package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html

#
# PR-AWS-0184-CFR
#

default vpc_subnet_autoip = null

aws_issue["vpc_subnet_autoip"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::subnet"
    lower(resource.Properties.MapPublicIpOnLaunch) == "true"
}

aws_bool_issue["vpc_subnet_autoip"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::subnet"
    resource.Properties.MapPublicIpOnLaunch == true
}

vpc_subnet_autoip {
    lower(input.Resources[i].Type) == "aws::ec2::subnet"
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
    "Policy Code": "PR-AWS-0184-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS VPC subnets should not allow automatic public IP assignment",
    "Policy Description": "This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html"
}


#
# PR-AWS-0339-CFR
#

default eip_instance_link = null

aws_issue["eip_instance_link"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::eip"
    lower(resource.Properties.Domain) == "vpc"
    not resource.Properties.InstanceId
}

aws_issue["eip_instance_link"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::eip"
    lower(resource.Properties.Domain) == "vpc"
    count(resource.Properties.InstanceId) == 0
}


aws_issue["eip_instance_link"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::eip"
    lower(resource.Properties.Domain) == "vpc"
    resource.Properties.InstanceId == null
}

eip_instance_link {
    lower(input.Resources[i].Type) == "aws::ec2::eip"
    not aws_issue["eip_instance_link"]
}

eip_instance_link = false {
    aws_issue["eip_instance_link"]
}

eip_instance_link_err = "Ensure all EIP addresses allocated to a VPC are attached related EC2 instances" {
    aws_issue["eip_instance_link"]
}

eip_instance_link_metadata := {
    "Policy Code": "PR-AWS-0339-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure all EIP addresses allocated to a VPC are attached related EC2 instances",
    "Policy Description": "Ensure that a managed Config rule for AWS Elastic IPs (EIPs) attached to EC2 instances launched inside a VPC is created. Config service tracks changes within your AWS resources configuration and saves the recorded data for security and compliance audits",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html"
}
