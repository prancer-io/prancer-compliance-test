package rule


#
# PR-AWS-TRF-ECR-001
#

default ecr_imagetag = null

aws_issue["ecr_imagetag"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    lower(resource.properties.image_tag_mutability) == "mutable"
}

source_path[{"ecr_imagetag": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    lower(resource.properties.image_tag_mutability) == "mutable"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "image_tag_mutability"]
        ],
    }
}

ecr_imagetag {
    lower(input.resources[i].type) == "aws_ecr_repository"
    not aws_issue["ecr_imagetag"]
}

ecr_imagetag = false {
    aws_issue["ecr_imagetag"]
}

ecr_imagetag_err = "Ensure ECR image tags are immutable" {
    aws_issue["ecr_imagetag"]
}

ecr_imagetag_metadata := {
    "Policy Code": "PR-AWS-TRF-ECR-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure ECR image tags are immutable",
    "Policy Description": "Amazon ECR supports immutable tags, preventing image tags from being overwritten. In the past, ECR tags could have been overwritten, this could be overcome by requiring users to uniquely identify an image using a naming convention.Tag Immutability enables users can rely on the descriptive tags of an image as a mechanism to track and uniquely identify images. By setting an image tag as immutable, developers can use the tag to correlate the deployed image version with the build that produced the image.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability"
}

#
# PR-AWS-TRF-ECR-002
#

default ecr_encryption = null

aws_attribute_absence["ecr_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    not resource.properties.encryption_configuration
}

source_path[{"ecr_imagetag": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    not resource.properties.encryption_configuration

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_configuration"]
        ],
    }
}

aws_issue["ecr_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    encryption_configuration := resource.properties.encryption_configuration[j]
    not encryption_configuration.encryption_type
}

source_path[{"ecr_imagetag": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    encryption_configuration := resource.properties.encryption_configuration[j]
    not encryption_configuration.encryption_type

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_configuration", j, "encryption_type"]
        ],
    }
}

ecr_encryption {
    lower(input.resources[i].type) == "aws_ecr_repository"
    not aws_issue["ecr_encryption"]
    not aws_attribute_absence["ecr_encryption"]
}

ecr_encryption = false {
    aws_issue["ecr_encryption"]
}

ecr_encryption = false {
    aws_attribute_absence["ecr_encryption"]
}

ecr_encryption_err = "Ensure ECR repositories are encrypted" {
    aws_issue["ecr_encryption"]
}

ecr_encryption_metadata := {
    "Policy Code": "PR-AWS-TRF-ECR-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure ECR repositories are encrypted",
    "Policy Description": "Make sure encryption_type is present in ECR encryption_configuration To increase control of the encryption and control the management of factors like key rotation",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability"
}

#
# PR-AWS-TRF-ECR-003
#

default ecr_scan = null

aws_bool_issue["ecr_scan"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    image_scanning_configuration := resource.properties.image_scanning_configuration[j]
    not image_scanning_configuration.scan_on_push
}

source_path[{"ecr_scan": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    image_scanning_configuration := resource.properties.image_scanning_configuration[j]
    not image_scanning_configuration.scan_on_push

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "image_scanning_configuration", j, "scan_on_push"]
        ],
    }
}

aws_issue["ecr_scan"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    image_scanning_configuration := resource.properties.image_scanning_configuration[j]
    lower(image_scanning_configuration.scan_on_push) != "true"
}

source_path[{"ecr_scan": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    image_scanning_configuration := resource.properties.image_scanning_configuration[j]
    lower(image_scanning_configuration.scan_on_push) != "true"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "image_scanning_configuration", j, "scan_on_push"]
        ],
    }
}

ecr_scan {
    lower(input.resources[i].type) == "aws_ecr_repository"
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
    "Policy Code": "PR-AWS-TRF-ECR-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure ECR image scan on push is enabled",
    "Policy Description": "Amazon ECR is a fully managed container registry used to store, manage and deploy container images. ECR Image Scanning assesses and identifies operating system vulnerabilities. Using automated image scans you can ensure container image vulnerabilities are found before getting pushed to production. ECR APIs notify if vulnerabilities were found when a scan completes",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-image_scanning_configuration.html#cfn-ecr-repository-image_scanning_configuration-scan_on_push"
}

#
# PR-AWS-TRF-ECR-004
#

default ecr_public_access_disable = null

aws_issue["ecr_public_access_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

source_path[{"ecr_scan": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
    metadata := {
        "resource_path": [
            ["resources", i, ".properties", "policy", "Statement", j, "Principal"]
        ],
    }
}

aws_issue["ecr_public_access_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

source_path[{"ecr_scan": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
    metadata := {
        "resource_path": [
            ["resources", i, ".properties", "policy", "Statement", j, "Principal", "AWS"]
        ],
    }
}

aws_issue["ecr_public_access_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[k] = "*"
}

source_path[{"ecr_scan": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository_policy"
    statement := resource.properties.policy.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[k] = "*"
    metadata := {
        "resource_path": [
            ["resources", i, ".properties", "policy", "Statement", j, "Principal", "AWS", k]
        ],
    }
}

ecr_public_access_disable {
    lower(input.resources[i].type) == "aws_ecr_repository_policy"
    not aws_issue["ecr_public_access_disable"]
}

ecr_public_access_disable = false {
    aws_issue["ecr_public_access_disable"]
}

ecr_public_access_disable_err = "Ensure AWS ECR Repository is not publicly accessible" {
    aws_issue["ecr_public_access_disable"]
}

ecr_public_access_disable_metadata := {
    "Policy Code": "PR-AWS-TRF-ECR-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS ECR Repository is not publicly accessible",
    "Policy Description": "Public AWS ECR Repository potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy"
}


#
# PR-AWS-TRF-ECR-005
#

default ecr_vulnerability = null

aws_issue["ecr_vulnerability"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_registry_scanning_configuration"
    not resource.properties.scan_type
}

aws_issue["ecr_vulnerability"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_registry_scanning_configuration"
    lower(resource.properties.scan_type) != "enhanced"
}

aws_issue["ecr_vulnerability"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_registry_scanning_configuration"
    count(resource.rule) == 0
}


aws_issue["ecr_vulnerability"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_registry_scanning_configuration"
    rule := resource.rule[_]
    lower(rule.scan_frequency) != "continuous_scan"
}

ecr_vulnerability {
    lower(input.resources[i].type) == "aws_ecr_registry_scanning_configuration"
    not aws_issue["ecr_vulnerability"]
}

ecr_vulnerability = false {
    aws_issue["ecr_vulnerability"]
}

ecr_vulnerability_err = "Enable Enhanced scan type for AWS ECR registry to detect vulnerability" {
    aws_issue["ecr_vulnerability"]
}

ecr_vulnerability_metadata := {
    "Policy Code": "PR-AWS-TRF-ECR-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Enable Enhanced scan type for AWS ECR registry to detect vulnerability",
    "Policy Description": "Enable Enhanced scan type for AWS ECR registry to detect vulnerability",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_registry_scanning_configuration"
}


#
# PR-AWS-TRF-ECR-006
#

default ecr_accessible_only_via_private_endpoint = null

aws_issue["ecr_accessible_only_via_private_endpoint"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository_policy"
    statement := resource.properties.policy.Statement[_]
    lower(statement.Effect) == "allow"
    not has_property(statement,"Condition")
}

aws_issue["ecr_accessible_only_via_private_endpoint"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository_policy"
    statement := resource.properties.policy.Statement[_]
    lower(statement.Effect) == "allow"
    not has_property(statement.Condition, "StringEquals")
}

aws_issue["ecr_accessible_only_via_private_endpoint"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository_policy"
    statement := resource.properties.policy.Statement[_]
    lower(statement.Effect) == "allow"
    not has_property(statement.Condition.StringEquals, "aws:SourceVpce")
}

ecr_accessible_only_via_private_endpoint {
    lower(input.resources[i].type) == "aws_ecr_repository_policy"
    not aws_issue["ecr_accessible_only_via_private_endpoint"]
}

ecr_accessible_only_via_private_endpoint = false {
    aws_issue["ecr_accessible_only_via_private_endpoint"]
}

ecr_accessible_only_via_private_endpoint_err = "Ensure ECR resources are accessible only via private endpoint." {
    aws_issue["ecr_accessible_only_via_private_endpoint"]
}

ecr_accessible_only_via_private_endpoint_metadata := {
    "Policy Code": "PR-AWS-TRF-ECR-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure ECR resources are accessible only via private endpoint.",
    "Policy Description": "It checks if the container registry is accessible over the internet, GS mandates to keep the container repository private from GS network only.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy"
}


#
# PR-AWS-TRF-ECR-007
#

default lifecycle_policy_is_enabled = null

aws_issue["lifecycle_policy_is_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_lifecycle_policy"
    rule := resource.properties.policy.rules[_]
    lower(rule.selection.tagStatus) == "tagged"
}

aws_issue["lifecycle_policy_is_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_lifecycle_policy"
    not resource.properties.policy
}

lifecycle_policy_is_enabled {
    lower(input.resources[i].type) == "aws_ecr_lifecycle_policy"
    not aws_issue["lifecycle_policy_is_enabled"]
}

lifecycle_policy_is_enabled = false {
    aws_issue["lifecycle_policy_is_enabled"]
}

lifecycle_policy_is_enabled_err = "Ensure lifecycle policy is enabled for ECR image repositories." {
    aws_issue["lifecycle_policy_is_enabled"]
}

lifecycle_policy_is_enabled_metadata := {
    "Policy Code": "PR-AWS-TRF-ECR-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure lifecycle policy is enabled for ECR image repositories.",
    "Policy Description": "It checks if a lifecycle policy is created for ECR. ECR lifecycle policies provide more control over the lifecycle management of images in a private repository.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_lifecycle_policy"
}