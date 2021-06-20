package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-0042-CFR
#

default ec2_iam_role = null

aws_attribute_absence["ec2_iam_role"] {
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

ec2_iam_role_err = "EC2 instance attribute IamInstanceProfile missing in the resource" {
    aws_attribute_absence["ec2_iam_role"]
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
