package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-0042-CFR
#

default ec2_iam_role = null

aws_attribute_absence["ec2_iam_role"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ec2::instance"
    not resource.Properties.IamInstanceProfile
}

aws_issue["ec2_iam_role"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ec2::instance"
    not startswith(lower(resource.Properties.IamInstanceProfile), "arn:")
}

ec2_iam_role {
    lower(input.resources[_].Type) == "aws::ec2::instance"
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

ec2_iam_role_miss_err = "EC2 instance attribute IamInstanceProfile missing in the resource" {
    aws_attribute_absence["ec2_iam_role"]
}
