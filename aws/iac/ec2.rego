package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html

#
# Id: 42
#

default ec2_iam_role = null

ec2_iam_role {
    lower(input.Type) == "aws::ec2::instance"
    startswith(lower(input.Properties.IamInstanceProfile), "arn:")
}

ec2_iam_role = false {
    lower(input.Type) == "aws::ec2::instance"
    not startswith(lower(input.Properties.IamInstanceProfile), "arn:")
}

ec2_iam_role = false {
    lower(input.Type) == "aws::ec2::instance"
    not input.Properties.IamInstanceProfile
}

ec2_iam_role_err = "AWS EC2 Instance IAM Role not enabled" {
    ec2_iam_role == false
}
