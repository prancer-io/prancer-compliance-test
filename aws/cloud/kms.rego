package rule

# https://docs.aws.amazon.com/kms/latest/APIReference/

#
# PR-AWS-CLD-KMS-001
#

default kms_key_rotation = false

kms_key_rotation = true {
    input.KeyRotationEnabled == true
}

kms_key_rotation_err = "AWS Customer Master Key (CMK) rotation is not enabled" {
    kms_key_rotation == false
}

kms_key_rotation_metadata := {
    "Policy Code": "PR-AWS-CLD-KMS-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Customer Master Key (CMK) rotation is not enabled",
    "Policy Description": "This policy identifies Customer Master Keys (CMKs) that are not enabled with key rotation. AWS KMS (Key Management Service) allows customers to create master keys to encrypt sensitive data in different services. As a security best practice, it is important to rotate the keys periodically so that if the keys are compromised, the data in the underlying service is still secure with the new keys.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html"
}

#
# PR-AWS-CLD-KMS-002
#

default kms_key_state = false

kms_key_state = true {
    # lower(resource.Type) == "aws::kms::key"
    input.KeyMetadata.Enabled == true
}

kms_key_state_err = "AWS KMS Customer Managed Key not in use" {
    not kms_key_state
}

kms_key_state_metadata := {
    "Policy Code": "PR-AWS-CLD-KMS-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS KMS Customer Managed Key not in use",
    "Policy Description": "This policy identifies KMS Customer Managed Keys(CMKs) which are not usable. When you create a CMK, it is enabled by default. If you disable a CMK or schedule it for deletion makes it unusable, it cannot be used to encrypt or decrypt data and AWS KMS does not rotate the backing keys until you re-enable it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html"
}