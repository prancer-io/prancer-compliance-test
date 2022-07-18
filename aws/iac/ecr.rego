package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

#
# PR-AWS-CFR-ECR-001
#

default ecr_imagetag = null

aws_issue["ecr_imagetag"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    lower(resource.Properties.ImageTagMutability) == "mutable"
}

source_path[{"ecr_imagetag": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    lower(resource.Properties.ImageTagMutability) == "mutable"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ImageTagMutability"]
        ],
    }
}

ecr_imagetag {
    lower(input.Resources[i].Type) == "aws::ecr::repository"
    not aws_issue["ecr_imagetag"]
}

ecr_imagetag = false {
    aws_issue["ecr_imagetag"]
}

ecr_imagetag_err = "Ensure ECR image tags are immutable" {
    aws_issue["ecr_imagetag"]
}

ecr_imagetag_metadata := {
    "Policy Code": "PR-AWS-CFR-ECR-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure ECR image tags are immutable",
    "Policy Description": "Amazon ECR supports immutable tags, preventing image tags from being overwritten. In the past, ECR tags could have been overwritten, this could be overcome by requiring users to uniquely identify an image using a naming convention.Tag Immutability enables users can rely on the descriptive tags of an image as a mechanism to track and uniquely identify images. By setting an image tag as immutable, developers can use the tag to correlate the deployed image version with the build that produced the image.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability"
}

#
# PR-AWS-CFR-ECR-002
#

default ecr_encryption = null

aws_issue["ecr_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    not resource.Properties.EncryptionConfiguration.EncryptionType
}

source_path[{"ecr_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    not resource.Properties.EncryptionConfiguration.EncryptionType
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionConfiguration", "EncryptionType"]
        ],
    }
}

ecr_encryption {
    lower(input.Resources[i].Type) == "aws::ecr::repository"
    not aws_issue["ecr_encryption"]
}

ecr_encryption = false {
    aws_issue["ecr_encryption"]
}

ecr_encryption_err = "Ensure ECR repositories are encrypted" {
    aws_issue["ecr_encryption"]
}

ecr_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-ECR-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure ECR repositories are encrypted",
    "Policy Description": "Make sure EncryptionType is present in ECR EncryptionConfiguration To increase control of the encryption and control the management of factors like key rotation",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability"
}


#
# PR-AWS-CFR-ECR-003
#

default ecr_scan = null

aws_bool_issue["ecr_scan"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    not resource.Properties.ImageScanningConfiguration.ScanOnPush
}

source_path[{"ecr_scan": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    not resource.Properties.ImageScanningConfiguration.ScanOnPush
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ImageScanningConfiguration", "ScanOnPush"]
        ],
    }
}

aws_issue["ecr_scan"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    lower(resource.Properties.ImageScanningConfiguration.ScanOnPush) != "true"
}

source_path[{"ecr_scan": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    lower(resource.Properties.ImageScanningConfiguration.ScanOnPush) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ImageScanningConfiguration", "ScanOnPush"]
        ],
    }
}

ecr_scan {
    lower(input.Resources[i].Type) == "aws::ecr::repository"
    not aws_issue["ecr_scan"]
    not aws_bool_issue["ecr_scan"]
}

ecr_scan = false {
    aws_issue["ecr_scan"]
}

ecr_scan = false {
    aws_bool_issue["ecr_scan"]
}

ecr_scan_err = "Ensure ECR image scan on push is enabled" {
    aws_issue["ecr_scan"]
} else = "Ensure ECR image scan on push is enabled" {
    aws_bool_issue["ecr_scan"]
}

ecr_scan_metadata := {
    "Policy Code": "PR-AWS-CFR-ECR-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure ECR image scan on push is enabled",
    "Policy Description": "Amazon ECR is a fully managed container registry used to store, manage and deploy container images. ECR Image Scanning assesses and identifies operating system vulnerabilities. Using automated image scans you can ensure container image vulnerabilities are found before getting pushed to production. ECR APIs notify if vulnerabilities were found when a scan completes",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-imagescanningconfiguration.html#cfn-ecr-repository-imagescanningconfiguration-scanonpush"
}


#
# PR-AWS-CFR-ECR-004
#

default ecr_public_access_disable = null

aws_issue["ecr_public_access_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    statement := resource.Properties.RepositoryPolicyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

source_path[{"ecr_scan": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    statement := resource.Properties.RepositoryPolicyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RepositoryPolicyText", "Statement", j, "Principal"]
        ],
    }
}

aws_issue["ecr_public_access_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    statement := resource.Properties.RepositoryPolicyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

source_path[{"ecr_scan": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    statement := resource.Properties.RepositoryPolicyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RepositoryPolicyText", "Statement", j, "Principal", "AWS"]
        ],
    }
}

aws_issue["ecr_public_access_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    statement := resource.Properties.RepositoryPolicyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[k] = "*"
}

source_path[{"ecr_scan": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    statement := resource.Properties.RepositoryPolicyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[k] = "*"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "RepositoryPolicyText", "Statement", j, "Principal", "AWS", k]
        ],
    }
}

ecr_public_access_disable {
    lower(input.Resources[i].Type) == "aws::ecr::repository"
    not aws_issue["ecr_public_access_disable"]
}

ecr_public_access_disable = false {
    aws_issue["ecr_public_access_disable"]
}

ecr_public_access_disable_err = "Ensure AWS ECR Repository is not publicly accessible" {
    aws_issue["ecr_public_access_disable"]
}

ecr_public_access_disable_metadata := {
    "Policy Code": "PR-AWS-CFR-ECR-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS ECR Repository is not publicly accessible",
    "Policy Description": "Public AWS ECR Repository potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-imagescanningconfiguration.html#cfn-ecr-repository-imagescanningconfiguration-scanonpush"
}


#
# PR-AWS-CFR-ECR-006
#

default ecr_accessible_only_via_private_endpoint = null

aws_issue["ecr_accessible_only_via_private_endpoint"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    statement := resource.Properties.RepositoryPolicyText.Statement[j]
    lower(statement.Effect) == "allow"
    not has_property(statement, "Condition")
}

aws_issue["ecr_accessible_only_via_private_endpoint"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    statement := resource.Properties.RepositoryPolicyText.Statement[j]
    lower(statement.Effect) == "allow"
    not has_property(statement.Condition, "StringEquals")
}

aws_issue["ecr_accessible_only_via_private_endpoint"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    statement := resource.Properties.RepositoryPolicyText.Statement[j]
    lower(statement.Effect) == "allow"
    not has_property(statement.Condition.StringEquals, "aws:SourceVpce")
}

ecr_accessible_only_via_private_endpoint {
    lower(input.Resources[i].Type) == "aws::ecr::repository"
    not aws_issue["ecr_accessible_only_via_private_endpoint"]
}

ecr_accessible_only_via_private_endpoint = false {
    aws_issue["ecr_accessible_only_via_private_endpoint"]
}

ecr_accessible_only_via_private_endpoint_err = "Ensure ECR resources are accessible only via private endpoint." {
    aws_issue["ecr_accessible_only_via_private_endpoint"]
}

ecr_accessible_only_via_private_endpoint_metadata := {
    "Policy Code": "PR-AWS-CFR-ECR-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure ECR resources are accessible only via private endpoint.",
    "Policy Description": "It checks if the container registry is accessible over the internet, GS mandates to keep the container repository private from GS network only.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html"
}


#
# PR-AWS-CFR-ECR-007
#

default lifecycle_policy_is_enabled = null

aws_issue["lifecycle_policy_is_enabled"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    rule := resource.Properties.LifecyclePolicy.LifecyclePolicyText.rules[_]
    lower(rules.selection.tagStatus) == "tagged"
}

aws_issue["lifecycle_policy_is_enabled"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    not resource.Properties.LifecyclePolicy.LifecyclePolicyText
}

lifecycle_policy_is_enabled {
    lower(input.Resources[i].Type) == "aws::ecr::repository"
    not aws_issue["lifecycle_policy_is_enabled"]
}

lifecycle_policy_is_enabled = false {
    aws_issue["lifecycle_policy_is_enabled"]
}

lifecycle_policy_is_enabled_err = "Ensure lifecycle policy is enabled for ECR image repositories." {
    aws_issue["lifecycle_policy_is_enabled"]
}

lifecycle_policy_is_enabled_metadata := {
    "Policy Code": "PR-AWS-CFR-ECR-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure lifecycle policy is enabled for ECR image repositories.",
    "Policy Description": "It checks if a lifecycle policy is created for ECR. ECR lifecycle policies provide more control over the lifecycle management of images in a private repository.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html"
}