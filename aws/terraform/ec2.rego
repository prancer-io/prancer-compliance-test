package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# PR-AWS-0042-TRF
#

default ec2_iam_role = null

aws_attribute_absence["ec2_iam_role"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_instance"
    not resource.properties.iam_instance_profile
}

aws_issue["ec2_iam_role"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_instance"
    not startswith(lower(resource.properties.iam_instance_profile), "arn:")
}

ec2_iam_role {
    lower(input.json.resources[_].type) == "aws_instance"
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
