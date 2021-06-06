package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html

#
# PR-AWS-0041-TRF
#

default ebs_encrypt = null

aws_issue["ebs_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_ebs_volume"
    not resource.properties.encrypted
}

ebs_encrypt {
    lower(input.resources[_].type) == "aws_ebs_volume"
    not aws_issue["ebs_encrypt"]
}

ebs_encrypt = false {
    aws_issue["ebs_encrypt"]
}

ebs_encrypt_err = "AWS EBS volumes are not encrypted" {
    aws_issue["ebs_encrypt"]
}

ebs_encrypt_metadata := {
    "Policy Code": "PR-AWS-0041-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS EBS volumes are not encrypted",
    "Policy Description": "This policy identifies the EBS volumes which are not encrypted. The snapshots that you take of an encrypted EBS volume are also encrypted and can be moved between AWS Regions as needed. You cannot share encrypted snapshots with other AWS accounts and you cannot make them public. It is recommended that EBS volume should be encrypted.",
    "Resource Type": "aws_ebs_volume",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html"
}
