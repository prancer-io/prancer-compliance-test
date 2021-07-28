package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html

#
# PR-AWS-0041-CFR
#

default ebs_encrypt = null

aws_issue["ebs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::volume"
    resource.Properties.Encrypted != true
    resource.Properties.Encrypted != "true"
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

ebs_encrypt_metadata := {
    "Policy Code": "PR-AWS-0041-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS EBS volumes are not encrypted",
    "Policy Description": "This policy identifies the EBS volumes which are not encrypted. The snapshots that you take of an encrypted EBS volume are also encrypted and can be moved between AWS Regions as needed. You cannot share encrypted snapshots with other AWS accounts and you cannot make them public. It is recommended that EBS volume should be encrypted.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html"
}
