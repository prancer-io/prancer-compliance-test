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

# The condition instance.IamInstanceProfile.Arn will be true, if the value exists in the ec2 collection created.
# Therefore the test case will pass.