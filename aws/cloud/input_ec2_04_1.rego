#
# PR-AWS-0039
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshotAttribute.html

rulepass = true {
    lower(input.Type) == "AWS::EC2::Volume"
    volumePermission := input.CreateVolumePermissions[_]
    volumePermission.UserId
}

rulepass = true {
    lower(input.Type) == "AWS::EC2::Volume"
    volumePermission := input.CreateVolumePermissions[_]
    volumePermission.Group != "all"
}

metadata := {
    "Policy Code": "PR-AWS-0039",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS EBS snapshots are accessible to public",
    "Policy Description": "This policy identifies EC2 EBS snapshots which are accessible to public. Amazon Elastic Block Store (Amazon EBS) provides persistent block storage volumes for use with Amazon EC2 instances in the AWS Cloud. If EBS snapshots are inadvertently shared to public, any unauthorized user with AWS console access can gain access to the snapshots and gain access to sensitive data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshotAttribute.html"
}

# The condition instance.IamInstanceProfile.Arn will be true, if the value exists in the ec2 collection created.
# Therefore the test case will pass.