package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html

#
# PR-AWS-0060-CFR
#

default efs_kms = null

aws_attribute_absence["efs_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    not resource.Properties.KmsKeyId
}

aws_issue["efs_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    not startswith(resource.Properties.KmsKeyId, "arn:")
}

aws_issue["efs_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    lower(resource.Properties.Encrypted) == "false"
}

aws_bool_issue["efs_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    not resource.Properties.Encrypted
}

efs_kms {
    lower(input.Resources[i].Type) == "aws::efs::filesystem"
    not aws_issue["efs_kms"]
    not aws_bool_issue["efs_kms"]
    not aws_attribute_absence["efs_kms"]
}

efs_kms = false {
    aws_issue["efs_kms"]
}

efs_kms = false {
    aws_bool_issue["efs_kms"]
}

efs_kms = false {
    aws_attribute_absence["efs_kms"]
}

efs_kms_err = "AWS Elastic File System (EFS) not encrypted using Customer Managed Key" {
    aws_issue["efs_kms"]
} else = "AWS Elastic File System (EFS) not encrypted using Customer Managed Key" {
    aws_bool_issue["efs_kms"]
}

efs_kms_miss_err = "EFS attribute KmsKeyId missing in the resource" {
    aws_attribute_absence["efs_kms"]
}

efs_kms_metadata := {
    "Policy Code": "PR-AWS-0060-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic File System (EFS) not encrypted using Customer Managed Key",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) which are encrypted with default KMS keys and not with Keys managed by Customer. It is a best practice to use customer managed KMS Keys to encrypt your EFS data. It gives you full control over the encrypted data.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}

#
# PR-AWS-0061-CFR
#

default efs_encrypt = null

aws_attribute_absence["efs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    not resource.Properties.Encrypted
}

aws_issue["efs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    lower(resource.Properties.Encrypted) != "true"
}
aws_bool_issue["efs_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::efs::filesystem"
    resource.Properties.Encrypted != true
}

efs_encrypt {
    lower(input.Resources[i].Type) == "aws::efs::filesystem"
    not aws_issue["efs_encrypt"]
    not aws_bool_issue["efs_encrypt"]
    not aws_attribute_absence["efs_encrypt"]
}

efs_encrypt = false {
    aws_issue["efs_encrypt"]
}

efs_encrypt = false {
    aws_bool_issue["efs_encrypt"]
}

efs_encrypt = false {
    aws_attribute_absence["efs_encrypt"]
}

efs_encrypt_err = "AWS Elastic File System (EFS) with encryption for data at rest disabled" {
    aws_issue["efs_encrypt"]
} else = "AWS Elastic File System (EFS) with encryption for data at rest disabled" {
    aws_bool_issue["efs_encrypt"]
}

efs_encrypt_miss_err = "EFS attribute Encrypted missing in the resource" {
    aws_attribute_absence["efs_encrypt"]
}

efs_encrypt_metadata := {
    "Policy Code": "PR-AWS-0061-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic File System (EFS) with encryption for data at rest disabled",
    "Policy Description": "This policy identifies Elastic File Systems (EFSs) for which encryption for data at rest disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to EFS.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}
