package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html

#
# Id: 41
#

default ebs_encrypt = null

aws_issue["ebs_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ec2::volume"
    not resource.Properties.Encrypted
}

ebs_encrypt {
    lower(input.resources[_].Type) == "aws::ec2::volume"
    not aws_issue["ebs_encrypt"]
}

ebs_encrypt = false {
    aws_issue["ebs_encrypt"]
}

ebs_encrypt_err = "AWS EBS volumes are not encrypted" {
    aws_issue["ebs_encrypt"]
}
