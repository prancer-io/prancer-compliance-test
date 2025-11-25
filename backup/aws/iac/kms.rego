package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html
#
# PR-AWS-CFR-KMS-001
#
default kms_key_rotation = null

aws_bool_issue["kms_key_rotation"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    not resource.Properties.EnableKeyRotation
}

source_path[{"kms_key_rotation": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    not resource.Properties.EnableKeyRotation
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EnableKeyRotation"]
        ],
    }
}

aws_issue["kms_key_rotation"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    lower(resource.Properties.EnableKeyRotation) == "false"
}

source_path[{"kms_key_rotation": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    lower(resource.Properties.EnableKeyRotation) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EnableKeyRotation"]
        ],
    }
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
    "Policy Code": "PR-AWS-CFR-KMS-001",
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
# PR-AWS-CFR-KMS-002
#
default kms_key_state = null

aws_bool_issue["kms_key_state"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    not resource.Properties.Enabled
}

source_path[{"kms_key_state": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    not resource.Properties.Enabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Enabled"]
        ],
    }
}

aws_issue["kms_key_state"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    lower(resource.Properties.Enabled) == "false"
}

source_path[{"kms_key_state": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    lower(resource.Properties.Enabled) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Enabled"]
        ],
    }
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
    "Policy Code": "PR-AWS-CFR-KMS-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS KMS Customer Managed Key not in use",
    "Policy Description": "This policy identifies KMS Customer Managed Keys(CMKs) which are not usable. When you create a CMK, it is enabled by default. If you disable a CMK or schedule it for deletion makes it unusable, it cannot be used to encrypt or decrypt data and AWS KMS does not rotate the backing keys until you re-enable it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html#cfn-kms-key-enabled"
}


#
# PR-AWS-CFR-KMS-003
#
default kms_key_allow_all_principal = null

aws_issue["kms_key_allow_all_principal"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    Statement := resource.Properties.KeyPolicy.Statement[j]
    Statement.Principal == "*"
}

source_path[{"kms_key_allow_all_principal": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    Statement := resource.Properties.KeyPolicy.Statement[j]
    Statement.Principal == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KeyPolicy", "Statement", j, "Principal"]
        ],
    }
}

aws_issue["kms_key_allow_all_principal"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    Statement := resource.Properties.KeyPolicy.Statement[j]
    Statement.Principal["AWS"] == "*"
}

source_path[{"kms_key_allow_all_principal": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::kms::key"
    Statement := resource.Properties.KeyPolicy.Statement[j]
    Statement.Principal["AWS"] == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KeyPolicy", "Statement", j, "Principal", "AWS"]
        ],
    }
}

kms_key_allow_all_principal {
    lower(input.Resources[i].Type) == "aws::kms::key"
    not aws_issue["kms_key_allow_all_principal"]
}

kms_key_allow_all_principal = false {
    aws_issue["kms_key_allow_all_principal"]
}

kms_key_allow_all_principal_err = "Ensure no KMS key policy contain wildcard (*) principal" {
    aws_issue["kms_key_allow_all_principal"]
}


kms_key_allow_all_principal_metadata := {
    "Policy Code": "PR-AWS-CFR-KMS-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure no KMS key policy contain wildcard (*) principal",
    "Policy Description": "This policy revents all user access to specific resource/s and actions",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html"
}

