package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability
#
# PR-AWS-0208-TRF
#

default ecr_imagetag = null

aws_issue["ecr_imagetag"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    lower(resource.properties.image_tag_mutability) == "mutable"
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
    "Policy Code": "PR-AWS-0208-TRF",
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
# PR-AWS-0209-TRF
#

default ecr_encryption = null

aws_issue["ecr_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    encryption_configuration := resource.properties.encryption_configuration[_]
    not encryption_configuration.encryption_type
}


ecr_encryption {
    lower(input.resources[i].type) == "aws_ecr_repository"
    not aws_issue["ecr_encryption"]
}

ecr_encryption = false {
    aws_issue["ecr_encryption"]
}

ecr_encryption_err = "Ensure ECR repositories are encrypted" {
    aws_issue["ecr_encryption"]
}

ecr_encryption_metadata := {
    "Policy Code": "PR-AWS-0209-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure ECR repositories are encrypted",
    "Policy Description": "Make sure encryption_type is present in ECR encryption_configuration To increase control of the encryption and control the management of factors like key rotation",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability"
}


#
# PR-AWS-0255-TRF
#

default ecr_scan = null

aws_bool_issue["ecr_scan"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    image_scanning_configuration := resource.properties.image_scanning_configuration[_]
    not image_scanning_configuration.scan_on_push
}

aws_issue["ecr_scan"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    image_scanning_configuration := resource.properties.image_scanning_configuration[_]
    lower(image_scanning_configuration.scan_on_push) != "true"
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
    "Policy Code": "PR-AWS-0255-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure ECR image scan on push is enabled",
    "Policy Description": "Amazon ECR is a fully managed container registry used to store, manage and deploy container images. ECR Image Scanning assesses and identifies operating system vulnerabilities. Using automated image scans you can ensure container image vulnerabilities are found before getting pushed to production. ECR APIs notify if vulnerabilities were found when a scan completes",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-image_scanning_configuration.html#cfn-ecr-repository-image_scanning_configuration-scan_on_push"
}

