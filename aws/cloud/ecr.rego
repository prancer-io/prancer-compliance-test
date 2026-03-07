package rule

import data.common

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imageTagMutability


#
# PR-AWS-CLD-ECR-001
#

default ecr_imagetag = null

ecr_imagetag_violation {
    repositories := input.repositories[_]
    lower(repositories.imageTagMutability) == "mutable"
}

ecr_imagetag {
    input.repositories
    not ecr_imagetag_violation
}

ecr_imagetag = false {
    ecr_imagetag_violation
}

ecr_imagetag_err = "Ensure ECR image tags are immutable" {
    not ecr_imagetag
}

ecr_imagetag_metadata := {
    "Policy Code": "PR-AWS-CLD-ECR-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure ECR image tags are immutable",
    "Policy Description": "Amazon ECR supports immutable tags, preventing image tags from being overwritten. In the past, ECR tags could have been overwritten, this could be overcome by requiring users to uniquely identify an image using a naming convention.Tag Immutability enables users can rely on the descriptive tags of an image as a mechanism to track and uniquely identify images. By setting an image tag as immutable, developers can use the tag to correlate the deployed image version with the build that produced the image.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imageTagMutability"
}

#
# PR-AWS-CLD-ECR-002
#

default ecr_encryption = null

ecr_encryption_violation {
    repositories := input.repositories[_]
    not repositories.encryptionConfiguration.encryptionType
}

ecr_encryption {
    input.repositories
    not ecr_encryption_violation
}

ecr_encryption = false {
    ecr_encryption_violation
}

ecr_encryption_err = "Ensure ECR repositories are encrypted" {
    not ecr_encryption
}

ecr_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-ECR-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure ECR repositories are encrypted",
    "Policy Description": "Make sure encryptionType is present in ECR encryptionConfiguration To increase control of the encryption and control the management of factors like key rotation",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imageTagMutability"
}


#
# PR-AWS-CLD-ECR-003
#

default ecr_scan = null

ecr_scan_violation {
    repositories := input.repositories[_]
    not repositories.imageScanningConfiguration.scanOnPush
}

ecr_scan_violation {
    repositories := input.repositories[_]
    lower(repositories.imageScanningConfiguration.scanOnPush) != "true"
}

ecr_scan {
    input.repositories
    not ecr_scan_violation
}

ecr_scan = false {
    ecr_scan_violation
}

ecr_scan_err = "Ensure ECR image scan on push is enabled" {
    not ecr_scan
}

ecr_scan_metadata := {
    "Policy Code": "PR-AWS-CLD-ECR-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure ECR image scan on push is enabled",
    "Policy Description": "Amazon ECR is a fully managed container registry used to store, manage and deploy container images. ECR Image Scanning assesses and identifies operating system vulnerabilities. Using automated image scans you can ensure container image vulnerabilities are found before getting pushed to production. ECR APIs notify if vulnerabilities were found when a scan completes",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-imageScanningConfiguration.html#cfn-ecr-repository-imageScanningConfiguration-scanOnPush"
}


#
# PR-AWS-CLD-ECR-004
#

default ecr_public_access_disable = null

ecr_public_access_disable_violation {
    policyText := json.unmarshal(input.policyText)
    statement := policyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

ecr_public_access_disable_violation {
    policyText := json.unmarshal(input.policyText)
    statement := policyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

ecr_public_access_disable_violation {
    policyText := json.unmarshal(input.policyText)
    statement := policyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[k] = "*"
}

ecr_public_access_disable {
    input.policyText
    not ecr_public_access_disable_violation
}

ecr_public_access_disable = false {
    ecr_public_access_disable_violation
}

ecr_public_access_disable_err = "Ensure AWS ECR Repository is not publicly accessible" {
    not ecr_public_access_disable
}

ecr_public_access_disable_metadata := {
    "Policy Code": "PR-AWS-CLD-ECR-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS ECR Repository is not publicly accessible",
    "Policy Description": "Public AWS ECR Repository potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-imageScanningConfiguration.html#cfn-ecr-repository-imageScanningConfiguration-scanOnPush"
}


#
# PR-AWS-CLD-ECR-005
#

default ecr_vulnerability = null

ecr_vulnerability_violation {
    lower(input.scanningConfiguration.scanType) != "enhanced"
}

ecr_vulnerability_violation {
    rule = input.scanningConfiguration.rules[_]
    lower(rule.scanFrequency) != "continuous_scan"
}

ecr_vulnerability_violation {
    count(input.scanningConfiguration.rules) == 0
}

ecr_vulnerability {
    input.scanningConfiguration
    not ecr_vulnerability_violation
}

ecr_vulnerability = false {
    ecr_vulnerability_violation
}

ecr_vulnerability_err = "Ensure ECR image scan on push is enabled" {
    not ecr_vulnerability
}

ecr_vulnerability_metadata := {
    "Policy Code": "PR-AWS-TRF-ECR-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "Aws Cloud",
    "Policy Title": "Enable Enhanced scan type for AWS ECR registry to detect vulnerability",
    "Policy Description": "Enable Enhanced scan type for AWS ECR registry to detect vulnerability",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_registry_scanning_configuration"
}

#
# PR-AWS-CLD-ECR-006
#

default ecr_accessible_only_via_private_endpoint = null

ecr_accessible_only_via_private_endpoint_violation {
    policy := json.unmarshal(input.policyText)
    policy_statement := policy.Statement[j]
    policy_statement.Condition
    lower(policy_statement.Effect) == "allow"
    not common.has_property(policy_statement.Condition.StringEquals, "aws:SourceVpce")
}

ecr_accessible_only_via_private_endpoint {
    input.policyText
    not ecr_accessible_only_via_private_endpoint_violation
}

ecr_accessible_only_via_private_endpoint = false {
    ecr_accessible_only_via_private_endpoint_violation
}

ecr_accessible_only_via_private_endpoint_err = "Ensure ECR resources are accessible only via private endpoint." {
    not ecr_accessible_only_via_private_endpoint
}

ecr_accessible_only_via_private_endpoint_metadata := {
    "Policy Code": "PR-AWS-TRF-ECR-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "Aws Cloud",
    "Policy Title": "Ensure ECR resources are accessible only via private endpoint.",
    "Policy Description": "It checks if the container registry is accessible over the internet, GS mandates to keep the container repository private from GS network only",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecr.html#ECR.Client.get_repository_policy"
}

#
# PR-AWS-CLD-ECR-007
#

default lifecycle_policy_is_enabled = null

lifecycle_policy_is_enabled_violation {
    not input.lifecyclePolicyText
}

lifecycle_policy_is_enabled_violation {
    lifecyclePolicy := json.unmarshal(input.lifecyclePolicyText)
    rule := lifecyclePolicy.rules[j]
    lower(rule.selection.tagStatus) == "tagged"
}

lifecycle_policy_is_enabled {
    input.lifecyclePolicyText
    not lifecycle_policy_is_enabled_violation
}

lifecycle_policy_is_enabled = false {
    lifecycle_policy_is_enabled_violation
}

lifecycle_policy_is_enabled_err = "Ensure lifecycle policy is enabled for ECR image repositories." {
    not lifecycle_policy_is_enabled
}

lifecycle_policy_is_enabled_metadata := {
    "Policy Code": "PR-AWS-TRF-ECR-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "Aws Cloud",
    "Policy Title": "Ensure lifecycle policy is enabled for ECR image repositories.",
    "Policy Description": "It checks if a lifecycle policy is created for ECR. ECR lifecycle policies provide more control over the lifecycle management of images in a private repository.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecr.html#ECR.Client.get_lifecycle_policy"
}


#
# PR-AWS-CLD-ECR-008
#
# AWS::KMS::Key
# AWS::ECR::Repository

default ecr_encrypted_using_key = null

ecr_encrypted_using_key_violation {
	ecr := input.TEST_ECR[_]
    X := ecr.repositories[i]
	lower(X.encryptionConfiguration.encryptionType) == "kms"
	common.has_property(X.encryptionConfiguration, "kmsKey")
	Y := input.TEST_KMS[_]
	X.encryptionConfiguration.kmsKey == Y.KeyMetadata.Arn
	Y.KeyMetadata.KeyManager != "CUSTOMER"
}

ecr_encrypted_using_key_violation {
	ecr := input.TEST_ECR[_]
    X := ecr.repositories[i]
	lower(X.encryptionConfiguration.encryptionType) == "kms"
	common.has_property(X.encryptionConfiguration, "kmsKey")
	Y := input.TEST_KMS[_]
	X.encryptionConfiguration.kmsKey == Y.KeyMetadata.KeyId
	Y.KeyMetadata.KeyManager != "CUSTOMER"
}

ecr_encrypted_using_key {
    input.TEST_ECR
    not ecr_encrypted_using_key_violation
}

ecr_encrypted_using_key = false {
    ecr_encrypted_using_key_violation
}

ecr_encrypted_using_key_err = "Ensure ECR is encrypted using dedicated GS managed KMS key." {
	not ecr_encrypted_using_key
}

ecr_encrypted_using_key_metadata := {
	"Policy Code": "PR-AWS-TRF-ECR-008",
	"Type": "cloud",
	"Product": "AWS",
	"Language": "Aws Cloud",
	"Policy Title": "Ensure ECR is encrypted using dedicated GS managed KMS key.",
	"Policy Description": "It checks if a GS managed KMS key (CMK) is used for ECR encryption instead of AWS provided keys.",
	"Resource Type": "",
	"Policy Help URL": "",
	"Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecr.html#ECR.Client.describe_repositories",
}
