package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html

#
# PR-AWS-0041-CFR
#

default ebs_encrypt = null

aws_issue["ebs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::volume"
    not resource.Properties.Encrypted
}

ebs_encrypt {
    lower(input.Resources[i].Type) == "aws::ec2::volume"
    not aws_issue["ebs_encrypt"]
}

ebs_encrypt = false {
    aws_issue["ebs_encrypt"]
}

ebs_encrypt_err = "AWS EBS volumes are not encrypted" {
    aws_issue["ebs_encrypt"]
}
