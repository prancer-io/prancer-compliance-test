package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html

#
# PR-AWS-0060-TRF
#

default efs_kms = null

aws_attribute_absence["efs_kms"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_efs_file_system"
    not resource.properties.kms_key_id
}

aws_issue["efs_kms"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_efs_file_system"
    not startswith(resource.properties.kms_key_id, "arn:")
}

aws_issue["efs_kms"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_efs_file_system"
    not resource.properties.encrypted
}

efs_kms {
    lower(input.resources[_].type) == "aws_efs_file_system"
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

efs_kms_miss_err = "EFS attribute kms_key_id missing in the resource" {
    aws_attribute_absence["efs_kms"]
}

efs_kms_metadata := {
    "Policy Code": "PR-AWS-0060-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic File System (EFS) not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your EFS data. It gives you full control over the encrypted data.",
    "Compliance": [],
    "Resource Type": "aws_efs_file_system",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}

#
# PR-AWS-0061-TRF
#

default efs_encrypt = null

aws_attribute_absence["efs_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_efs_file_system"
    not resource.properties.encrypted
}

aws_issue["efs_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_efs_file_system"
    resource.properties.encrypted != true
}

efs_encrypt {
    lower(input.resources[_].type) == "aws_efs_file_system"
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

efs_encrypt_miss_err = "EFS attribute encrypted missing in the resource" {
    aws_attribute_absence["efs_encrypt"]
}

efs_encrypt_metadata := {
    "Policy Code": "PR-AWS-0061-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic File System (EFS) with encryption for data at rest disabled",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) for which encryption for data at rest disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to EFS.",
    "Compliance": [],
    "Resource Type": "aws_efs_file_system",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}
