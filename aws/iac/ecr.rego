package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability
#
# PR-AWS-0208-CFR
#

default ecr_imagetag = null

aws_issue["ecr_imagetag"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    lower(resource.Properties.ImageTagMutability) == "mutable"
}


ecr_imagetag {
    lower(input.Resources[i].Type) == "aws::ecr::repository"
    not aws_issue["ecr_imagetag"]
}

ecr_imagetag = false {
    aws_issue["ecr_imagetag"]
}

ecr_imagetag = "Ensure no ECR imageTagMutability equals MUTABLE" {
    aws_issue["ecr_imagetag"]
}

ecr_imagetag_metadata := {
    "Policy Code": "PR-AWS-0208-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure no ECR imageTagMutability equals MUTABLE",
    "Policy Description": "Ensure no ECR imageTagMutability equals MUTABLE",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability"
}

#
# PR-AWS-0209-CFR
#

default ecr_encryption = null

aws_issue["ecr_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ecr::repository"
    not resource.Properties.EncryptionConfiguration.EncryptionType
}


ecr_encryption {
    lower(input.Resources[i].Type) == "aws::ecr::repository"
    not aws_issue["ecr_encryption"]
}

ecr_encryption = false {
    aws_issue["ecr_encryption"]
}

ecr_encryption = "Ensure encryption is enabled for ECR" {
    aws_issue["ecr_encryption"]
}

ecr_encryption_metadata := {
    "Policy Code": "PR-AWS-0209-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure encryption is enabled for ECR",
    "Policy Description": "Ensure encryption is enabled for ECR",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html#cfn-ecr-repository-imagetagmutability"
}

