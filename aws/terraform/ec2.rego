package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-0042-TRF
#

default ec2_iam_role = null

aws_attribute_absence["ec2_iam_role"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_instance"
    not resource.properties.iam_instance_profile
}

aws_issue["ec2_iam_role"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_instance"
    count(resource.properties.iam_instance_profile) == 0
}

ec2_iam_role {
    lower(input.resources[_].type) == "aws_instance"
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
}

ec2_iam_role_miss_err = "EC2 instance attribute iam_instance_profile missing in the resource" {
    aws_attribute_absence["ec2_iam_role"]
}

ec2_iam_role_metadata := {
    "Policy Code": "PR-AWS-0042-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS EC2 Instance IAM Role not enabled",
    "Policy Description": "AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.",
    "Resource Type": "aws_instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}
