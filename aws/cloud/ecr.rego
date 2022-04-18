package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imageTagMutability
#
# PR-AWS-CLD-ECR-001
#

default ecr_imagetag = true

ecr_imagetag = false {
    # lower(resource.Type) == "aws::ecr::repository"
    repositories := input.repositories[_]
    lower(repositories.imageTagMutability) == "mutable"
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

default ecr_encryption = true

ecr_encryption = false {
    # lower(resource.Type) == "aws::ecr::repository"
    repositories := input.repositories[_]
    not repositories.encryptionConfiguration.encryptionType
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

default ecr_scan = true

ecr_scan = false {
    # lower(resource.Type) == "aws::ecr::repository"
    repositories := input.repositories[_]
    not repositories.imageScanningConfiguration.scanOnPush
}

ecr_scan = false {
    # lower(resource.Type) == "aws::ecr::repository"
    repositories := input.repositories[_]
    lower(repositories.imageScanningConfiguration.scanOnPush) != "true"
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

default ecr_public_access_disable = true

ecr_public_access_disable = false {
    # lower(resource.Type) == "aws::ecr::repository"
    policyText := json.unmarshal(input.policyText)
    statement := policyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal == "*"
}

ecr_public_access_disable = false {
    # lower(resource.Type) == "aws::ecr::repository"
    policyText := json.unmarshal(input.policyText)
    statement := policyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS == "*"
}

ecr_public_access_disable = false {
    # lower(resource.Type) == "aws::ecr::repository"
    policyText := json.unmarshal(input.policyText)
    statement := policyText.Statement[j]
    lower(statement.Effect) == "allow"
    statement.Principal.AWS[k] = "*"
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

default ecr_vulnerability = true

ecr_vulnerability = false {
    # lower(resource.Type) == "aws::ecr::repository"
    lower(input.scanningConfiguration.scanType) != "enhanced"
}

ecr_vulnerability = false {
    # lower(resource.Type) == "aws::ecr::repository"
    rule = input.scanningConfiguration.rules[_]
    lower(rule.scanFrequency) != "continuous_scan"
}

ecr_vulnerability = false {
    # lower(resource.Type) == "aws::ecr::repository"
    count(input.scanningConfiguration.rules) == 0
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
