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

#
# PR-AWS-CLD-KMS-003
# aws::kms::key

default kms_key_not_schedule_deletion = true

kms_key_not_schedule_deletion = false {
    lower(input.KeyMetadata.KeyState) == "pendingdeletion"
}

kms_key_not_schedule_deletion_err = "Ensure AWS KMS Key is not scheduled for deletion." {
    not kms_key_not_schedule_deletion
}

kms_key_not_schedule_deletion_metadata := {
    "Policy Code": "PR-AWS-CLD-KMS-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS KMS Key is not scheduled for deletion.",
    "Policy Description": "It identifies KMS Keys which are scheduled for deletion. Deleting keys in AWS KMS is destructive and potentially dangerous. It deletes the key material and all metadata associated with it and is irreversible. After a key is deleted, you can no longer decrypt the data that was encrypted under that key, which means that data becomes unrecoverable. You should delete a key only when you are sure that you don't need to use it anymore. If you are not sure, It is recommended that to disable the key instead of deleting it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html#KMS.Client.describe_key"
}
