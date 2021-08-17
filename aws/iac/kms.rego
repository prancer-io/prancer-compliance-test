package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html
#
# PR-AWS-0235-CFR
#
default kms_key_rotation = null

aws_bool_issue["kms_key_rotation"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    not resource.Properties.EnableKeyRotation
}

aws_issue["kms_key_rotation"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    lower(resource.Properties.EnableKeyRotation) == "false"
}

kms_key_rotation {
    lower(input.Resources[i].Type) == "aws::kms::key"
    not aws_issue["kms_key_rotation"]
    not aws_bool_issue["kms_key_rotation"]
}

kms_key_rotation = false {
    aws_issue["kms_key_rotation"]
}

kms_key_rotation = false {
    aws_bool_issue["kms_key_rotation"]
}

kms_key_rotation_err = "AWS Customer Master Key (CMK) rotation is not enabled" {
    aws_issue["kms_key_rotation"]
} else = "AWS Customer Master Key (CMK) rotation is not enabled" {
    aws_bool_issue["kms_key_rotation"]
}


kms_key_rotation_metadata := {
    "Policy Code": "PR-AWS-0235-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Customer Master Key (CMK) rotation is not enabled",
    "Policy Description": "This policy identifies Customer Master Keys (CMKs) that are not enabled with key rotation. AWS KMS (Key Management Service) allows customers to create master keys to encrypt sensitive data in different services. As a security best practice, it is important to rotate the keys periodically so that if the keys are compromised, the data in the underlying service is still secure with the new keys.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enablekeyrotation"
}


#
# PR-AWS-0236-CFR
#
default kms_key_state = null

aws_bool_issue["kms_key_state"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    not resource.Properties.Enabled
}

aws_issue["kms_key_state"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    lower(resource.Properties.Enabled) == "false"
}

kms_key_state {
    lower(input.Resources[i].Type) == "aws::kms::key"
    not aws_issue["kms_key_state"]
    not aws_bool_issue["kms_key_state"]
}

kms_key_state = false {
    aws_issue["kms_key_state"]
}

kms_key_state = false {
    aws_bool_issue["kms_key_state"]
}

kms_key_state_err = "AWS KMS Customer Managed Key not in use" {
    aws_issue["kms_key_state"]
} else = "AWS KMS Customer Managed Key not in use" {
    aws_bool_issue["kms_key_state"]
}


kms_key_state_metadata := {
    "Policy Code": "PR-AWS-0236-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS KMS Customer Managed Key not in use",
    "Policy Description": "This policy identifies KMS Customer Managed Keys(CMKs) which are not usable. When you create a CMK, it is enabled by default. If you disable a CMK or schedule it for deletion makes it unusable, it cannot be used to encrypt or decrypt data and AWS KMS does not rotate the backing keys until you re-enable it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enabled"
}

