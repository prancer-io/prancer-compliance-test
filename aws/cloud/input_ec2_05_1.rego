#
# PR-AWS-0042
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html
# Id: 42

rulepass {
    # lower(input.json.Type) == "aws::ec2::instance"
    instance := input.json.Reservations[_].Instances[_]
    instance.IamInstanceProfile.Arn
}

metadata := {
    "Policy Code": "PR-AWS-0042",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS EC2 Instance IAM Role not enabled",
    "Policy Description": "AWS provides Identity Access Management (IAM) roles to securely access AWS services and resources. The role is an identity with permission policies that define what the identity can and cannot do in AWS. As a best practice, create IAM roles and attach the role to manage EC2 instance permissions securely instead of distributing or sharing keys or passwords.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html"
}

# The condition instance.IamInstanceProfile.Arn will be true, if the value exists in the ec2 collection created.
# Therefore the test case will pass.
