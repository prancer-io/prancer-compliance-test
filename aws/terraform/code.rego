package rule


#
# PR-AWS-TRF-CB-001
#

default codebuild_encryption_disable = null

aws_issue["codebuild_encryption_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codebuild_project"
    artifacts := resource.properties.artifacts[j]
    artifacts.encryption_disabled == true
}

source_path[{"codebuild_encryption_disable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codebuild_project"
    artifacts := resource.properties.artifacts[j]
    artifacts.encryption_disabled == true
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "Artifacts", j, "encryption_disabled"]
        ],
    }
}

aws_issue["codebuild_encryption_disable"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codebuild_project"
    artifacts := resource.properties.artifacts[j]
    lower(artifacts.encryption_disabled) == "true"
}

source_path[{"codebuild_encryption_disable": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codebuild_project"
    artifacts := resource.properties.artifacts[j]
    lower(artifacts.encryption_disabled) == "true"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "Artifacts", j, "encryption_disabled"]
        ],
    }
}

codebuild_encryption_disable {
    lower(input.resources[i].type) == "aws_codebuild_project"
    not aws_issue["codebuild_encryption_disable"]
}

codebuild_encryption_disable = false {
    aws_issue["codebuild_encryption_disable"]
}

codebuild_encryption_disable_err = "Ensure CodeBuild project Artifact encryption is not disabled" {
    aws_issue["codebuild_encryption_disable"]
}

codebuild_encryption_disable_metadata := {
    "Policy Code": "PR-AWS-TRF-CB-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure CodeBuild project Artifact encryption is not disabled",
    "Policy Description": "AWS CodeBuild is a fully managed build service in the cloud. CodeBuild compiles your source code, runs unit tests, and produces artifacts that are ready to deploy. Build artifacts, such as a cache, logs, exported raw test report data files, and build results, are encrypted by default using CMKs for Amazon S3 that are managed by the AWS Key Management Service. If you do not want to use these CMKs, you must create and configure a customer-managed CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project"
}


#
# PR-AWS-TRF-CB-002
#

default codebuild_encryption = null

aws_issue["codebuild_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codebuild_project"
    not resource.properties.encryption_key
}

source_path[{"codebuild_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codebuild_project"
    not resource.properties.encryption_key
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_key"]
        ],
    }
}

aws_issue["codebuild_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codebuild_project"
    count(resource.properties.encryption_key) == 0
}

source_path[{"codebuild_encryption": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codebuild_project"
    count(resource.properties.encryption_key) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "encryption_key"]
        ],
    }
}

codebuild_encryption {
    lower(input.resources[i].type) == "aws_codebuild_project"
    not aws_issue["codebuild_encryption"]
}

codebuild_encryption = false {
    aws_issue["codebuild_encryption"]
}

codebuild_encryption_err = "Ensure that CodeBuild projects are encrypted using CMK" {
    aws_issue["codebuild_encryption"]
}

codebuild_encryption_metadata := {
    "Policy Code": "PR-AWS-TRF-CB-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that CodeBuild projects are encrypted using CMK",
    "Policy Description": "The AWS Key Management Service customer master key (CMK) to be used for encrypting the build output artifacts",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_key"
}


#
# PR-AWS-TRF-CD-001
#

default deploy_compute_platform = null

aws_issue["deploy_compute_platform"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codedeploy_app"
    not resource.properties.compute_platform
}

source_path[{"deploy_compute_platform": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codedeploy_app"
    not resource.properties.compute_platform

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "compute_platform"]
        ],
    }
}

aws_issue["deploy_compute_platform"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codedeploy_app"
    lower(resource.properties.compute_platform) != "ecs"
    lower(resource.properties.compute_platform) != "lambda"
}

source_path[{"deploy_compute_platform": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codedeploy_app"
    lower(resource.properties.compute_platform) != "ecs"
    lower(resource.properties.compute_platform) != "lambda"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "compute_platform"]
        ],
    }
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

default cp_artifact_encrypt = null

aws_attribute_absence["cp_artifact_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codepipeline"
    artifact_store := resource.properties.artifact_store[j]
    encryption_key  := artifact_store.encryption_key[k]
    not encryption_key.id
}

source_path[{"cp_artifact_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codepipeline"
    artifact_store := resource.properties.artifact_store[j]
    encryption_key  := artifact_store.encryption_key[k]
    not encryption_key.id

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "artifact_store", j, "encryption_key", k, "id"]
        ],
    }
}

aws_issue["cp_artifact_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codepipeline"
    artifact_store := resource.properties.artifact_store[j]
    encryption_key  := artifact_store.encryption_key[k]
    encryption_key.id
    lower(encryption_key.type) != "kms"
}

source_path[{"cp_artifact_encrypt": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codepipeline"
    artifact_store := resource.properties.artifact_store[j]
    encryption_key  := artifact_store.encryption_key[k]
    encryption_key.id
    lower(encryption_key.type) != "kms"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "artifact_store", j, "encryption_key", k, "type"]
        ],
    }
}

cp_artifact_encrypt {
    lower(input.resources[i].type) == "aws_codepipeline"
    not aws_issue["cp_artifact_encrypt"]
    not aws_attribute_absence["cp_artifact_encrypt"]
}

cp_artifact_encrypt = false {
    aws_issue["cp_artifact_encrypt"]
}

cp_artifact_encrypt = false {
    aws_attribute_absence["cp_artifact_encrypt"]
}

cp_artifact_encrypt_err = "Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled" {
    aws_issue["cp_artifact_encrypt"]
} else = "Code Pipeline encryption_key absent" {
    aws_attribute_absence["cp_artifact_encrypt"]
}


cp_artifact_encrypt_metadata := {
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