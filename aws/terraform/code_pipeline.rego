package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform
#
# PR-AWS-0206-TRF
#

default deploy_compute_platform = null

aws_attribute_absence["deploy_compute_platform"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codepipeline"
    artifact_store := resource.properties.artifact_store[_]
    encryption_key  := artifact_store.encryption_key[_]
    not encryption_key.id
}

aws_issue["deploy_compute_platform"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codepipeline"
    artifact_store := resource.properties.artifact_store[_]
    encryption_key  := artifact_store.encryption_key[_]
    encryption_key.id
    lower(encryption_key.type) != "cmk"
}


deploy_compute_platform {
    lower(input.resources[i].type) == "aws_codepipeline"
    not aws_issue["deploy_compute_platform"]
    not aws_attribute_absence["deploy_compute_platform"]
}

deploy_compute_platform = false {
    aws_issue["deploy_compute_platform"]
}

deploy_compute_platform = false {
    aws_attribute_absence["deploy_compute_platform"]
}

deploy_compute_platform_err = "Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled" {
    aws_issue["deploy_compute_platform"]
} else = "Code Pipeline encryption_key absent" {
    aws_attribute_absence["deploy_compute_platform"]
}


deploy_compute_platform_metadata := {
    "Policy Code": "PR-AWS-0206-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled",
    "Policy Description": "The type of encryption key When creating or updating a pipeline, the value must be cmk(customer-managed key)",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform"
}
