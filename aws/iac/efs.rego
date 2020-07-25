package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html

#
# Id: 60
#

default efs_kms = null

aws_attribute_absence["efs_kms"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::efs::filesystem"
    not resource.Properties.KmsKeyId
}

aws_issue["efs_kms"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::efs::filesystem"
    not startswith(resource.Properties.KmsKeyId, "arn:")
}

aws_issue["efs_kms"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::efs::filesystem"
    not resource.Properties.Encrypted
}

efs_kms {
    lower(input.resources[_].Type) == "aws::efs::filesystem"
    not aws_issue["efs_kms"]
    not aws_attribute_absence["efs_kms"]
}

efs_kms = false {
    aws_issue["efs_kms"]
}

efs_kms = false {
    aws_attribute_absence["efs_kms"]
}

efs_kms_err = "AWS Elastic File System (EFS) not encrypted using Customer Managed Key" {
    aws_issue["efs_kms"]
}

efs_kms_miss_err = "EFS attribute KmsKeyId missing in the resource" {
    aws_attribute_absence["efs_kms"]
}

#
# Id: 61
#

default efs_encrypt = null

aws_attribute_absence["efs_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::efs::filesystem"
    not resource.Properties.Encrypted
}

aws_issue["efs_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::efs::filesystem"
    resource.Properties.Encrypted != true
}

efs_encrypt {
    lower(input.resources[_].Type) == "aws::efs::filesystem"
    not aws_issue["efs_encrypt"]
    not aws_attribute_absence["efs_encrypt"]
}

efs_encrypt = false {
    aws_issue["efs_encrypt"]
}

efs_encrypt = false {
    aws_attribute_absence["efs_encrypt"]
}

efs_encrypt_err = "AWS Elastic File System (EFS) with encryption for data at rest disabled" {
    aws_issue["efs_encrypt"]
}

efs_encrypt_miss_err = "EFS attribute agentPoolProfiles missing in the resource" {
    aws_attribute_absence["efs_encrypt"]
}
