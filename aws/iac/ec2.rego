package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-0042-CFR
#

default ec2_iam_role = null

aws_issue["ec2_iam_role"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.IamInstanceProfile
}

aws_issue["ec2_iam_role"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not startswith(lower(resource.Properties.IamInstanceProfile), "arn:")
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
    "Policy Code": "PR-AWS-0042-CFR",
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
# PR-AWS-0045-CFR
#

default ec2_no_vpc = null

aws_issue["ec2_no_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.SubnetId
    count([c | resource.Properties.NetworkInterfaces[_].SubnetId; c := 1]) == 0
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
    "Policy Code": "PR-AWS-0045-CFR",
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
# PR-AWS-0046-CFR
#

default ec2_public_ip = null

aws_issue["ec2_public_ip"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::instance"
    resource.Properties.NetworkInterfaces[_].AssociatePublicIpAddress == true
}

ec2_public_ip {
    lower(input.Resources[i].Type) == "aws::ec2::instance"
    not aws_issue["ec2_public_ip"]
}

ec2_public_ip = false {
    aws_issue["ec2_public_ip"]
}

ec2_public_ip_err = "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access" {
    aws_issue["ec2_public_ip"]
}

ec2_public_ip_metadata := {
    "Policy Code": "PR-AWS-0046-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EC2 instances with Public IP and associated with Security Groups have Internet Access",
    "Policy Description": "This policy identifies AWS EC2 instances with Public IP and associated with Security Groups have Internet Access. EC2 instance receives a public IP address when launched in a default VPC security group (A security group acts as a virtual firewall for your instance to control inbound and outbound traffic.) and we don't assign a public IP address to instances launched in a non-default subnet. Therefore it's a best practice to ensure that there are no EC2 instances with Public IP that are associated with Security Groups which have Internet Access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}
