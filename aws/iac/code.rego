package rule

#
# PR-AWS-CFR-CB-001
#

default codebuild_encryption_disable = null

aws_issue["codebuild_encryption_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codebuild::project"
    resource.Properties.Artifacts.EncryptionDisabled == true
}

aws_issue["codebuild_encryption_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codebuild::project"
    lower(resource.Properties.Artifacts.EncryptionDisabled) == "true"
}

codebuild_encryption_disable {
    lower(input.Resources[i].Type) == "aws::codebuild::project"
    not aws_issue["codebuild_encryption_disable"]
}

codebuild_encryption_disable = false {
    aws_issue["codebuild_encryption_disable"]
}

codebuild_encryption_disable_err = "Ensure CodeBuild project Artifact encryption is not disabled" {
    aws_issue["codebuild_encryption_disable"]
}

codebuild_encryption_disable_metadata := {
    "Policy Code": "PR-AWS-CFR-CB-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure CodeBuild project Artifact encryption is not disabled",
    "Policy Description": "AWS CodeBuild is a fully managed build service in the cloud. CodeBuild compiles your source code, runs unit tests, and produces artifacts that are ready to deploy. Build artifacts, such as a cache, logs, exported raw test report data files, and build results, are encrypted by default using CMKs for Amazon S3 that are managed by the AWS Key Management Service. If you do not want to use these CMKs, you must create and configure a customer-managed CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html#cfn-codebuild-project-artifacts-encryptiondisabled"
}


#
# PR-AWS-CFR-CB-002
#

default codebuild_encryption = null

aws_issue["codebuild_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codebuild::project"
    not resource.Properties.EncryptionKey
}

aws_issue["codebuild_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codebuild::project"
    count(resource.Properties.EncryptionKey) == 0
}

codebuild_encryption {
    lower(input.Resources[i].Type) == "aws::codebuild::project"
    not aws_issue["codebuild_encryption"]
}

codebuild_encryption = false {
    aws_issue["codebuild_encryption"]
}

codebuild_encryption_err = "Ensure that CodeBuild projects are encrypted using CMK" {
    aws_issue["codebuild_encryption"]
}

codebuild_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-CB-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that CodeBuild projects are encrypted using CMK",
    "Policy Description": "The AWS Key Management Service customer master key (CMK) to be used for encrypting the build output artifacts",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html#cfn-codebuild-project-encryptionkey"
}


#
# PR-AWS-CFR-CP-001
#

default cp_artifact_encrypt = null

aws_attribute_absence["cp_artifact_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codepipeline::pipeline"
    not resource.Properties.ArtifactStore.EncryptionKey.Id
}

aws_issue["cp_artifact_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codepipeline::pipeline"
    resource.Properties.ArtifactStore.EncryptionKey.Id
    lower(resource.Properties.ArtifactStore.EncryptionKey.Type) != "kms"
}


cp_artifact_encrypt {
    lower(input.Resources[i].Type) == "aws::codepipeline::pipeline"
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
} else = "Code Pipeline EncryptionKey absent" {
    aws_attribute_absence["cp_artifact_encrypt"]
}


cp_artifact_encrypt_metadata := {
    "Policy Code": "PR-AWS-CFR-CP-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled",
    "Policy Description": "The type of encryption key When creating or updating a pipeline, the value must be cmk(customer-managed key)",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform"
}

#
# PR-AWS-CFR-CD-001
#

default deploy_compute_platform = null

aws_issue["deploy_compute_platform"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codedeploy::application"
    not resource.Properties.ComputePlatform
}

aws_issue["deploy_compute_platform"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codedeploy::application"
    lower(resource.Properties.ComputePlatform) != "ecs"
    lower(resource.Properties.ComputePlatform) != "lambda"
}


deploy_compute_platform {
    lower(input.Resources[i].Type) == "aws::codedeploy::application"
    not aws_issue["deploy_compute_platform"]
}

deploy_compute_platform = false {
    aws_issue["deploy_compute_platform"]
}

deploy_compute_platform_err = "AWS CodeDeploy application compute platform must be ECS or Lambda" {
    aws_issue["deploy_compute_platform"]
}


deploy_compute_platform_metadata := {
    "Policy Code": "PR-AWS-CFR-CD-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CodeDeploy application compute platform must be ECS or Lambda",
    "Policy Description": "AWS CodeDeploy application compute platform must be ECS or Lambda",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform"
}
