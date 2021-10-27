package rule


#
# PR-AWS-TRF-CD-001
#

default deploy_compute_platform = null

aws_issue["deploy_compute_platform"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codedeploy_app"
    not resource.properties.compute_platform
}

aws_issue["deploy_compute_platform"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codedeploy_app"
    lower(resource.properties.compute_platform) != "ecs"
    lower(resource.properties.compute_platform) != "lambda"
}


deploy_compute_platform {
    lower(input.resources[i].type) == "aws_codedeploy_app"
    not aws_issue["deploy_compute_platform"]
}

deploy_compute_platform = false {
    aws_issue["deploy_compute_platform"]
}

deploy_compute_platform_err = "AWS CodeDeploy application compute platform must be ECS or Lambda" {
    aws_issue["deploy_compute_platform"]
}


deploy_compute_platform_metadata := {
    "Policy Code": "PR-AWS-TRF-CD-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CodeDeploy application compute platform must be ECS or Lambda",
    "Policy Description": "AWS CodeDeploy application compute platform must be ECS or Lambda",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform"
}

#
# PR-AWS-TRF-CP-001
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
    lower(encryption_key.type) != "kms"
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
    "Policy Code": "PR-AWS-TRF-CP-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled",
    "Policy Description": "The type of encryption key When creating or updating a pipeline, the value must be cmk(customer-managed key)",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform"
}