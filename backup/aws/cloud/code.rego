package rule

#
# PR-AWS-CLD-CB-001
#

default codebuild_encryption_disable = true

codebuild_encryption_disable = false {
    # lower(resource.Type) == "aws::codebuild::project"
    projects := input.projects[_]
    projects.artifacts.encryptionDisabled == true
}

codebuild_encryption_disable_err = "Ensure CodeBuild project Artifact encryption is not disabled" {
    not codebuild_encryption_disable
}

codebuild_encryption_disable_metadata := {
    "Policy Code": "PR-AWS-CLD-CB-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure CodeBuild project Artifact encryption is not disabled",
    "Policy Description": "AWS CodeBuild is a fully managed build service in the cloud. CodeBuild compiles your source code, runs unit tests, and produces artifacts that are ready to deploy. Build artifacts, such as a cache, logs, exported raw test report data files, and build results, are encrypted by default using CMKs for Amazon S3 that are managed by the AWS Key Management Service. If you do not want to use these CMKs, you must create and configure a customer-managed CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html#cfn-codebuild-project-artifacts-encryptiondisabled"
}


#
# PR-AWS-CLD-CB-002
#

default codebuild_encryption = true

codebuild_encryption = false {
    # lower(resource.Type) == "aws::codebuild::project"
    projects := input.projects[_]
    not projects.encryptionKey
}

codebuild_encryption = false {
    # lower(resource.Type) == "aws::codebuild::project"
    projects := input.projects[_]
    count(projects.encryptionKey) == 0
}

codebuild_encryption_err = "Ensure that CodeBuild projects are encrypted using CMK" {
    not codebuild_encryption
}

codebuild_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-CB-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that CodeBuild projects are encrypted using CMK",
    "Policy Description": "The AWS Key Management Service customer master key (CMK) to be used for encrypting the build output artifacts",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html#cfn-codebuild-project-encryptionKey"
}


#
# PR-AWS-CLD-CP-001
#

default cp_artifact_encrypt = true

cp_artifact_encrypt = false {
    # lower(resource.Type) == "aws::codepipeline::pipeline"
    not input.pipeline.artifactStore.encryptionKey.id
}

cp_artifact_encrypt = false {
    # lower(resource.Type) == "aws::codepipeline::pipeline"
    input.pipeline.artifactStore.encryptionKey.id
    lower(input.pipeline.artifactStore.encryptionKey.type) != "kms"
}

cp_artifact_encrypt_err = "Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled" {
    not cp_artifact_encrypt
}

cp_artifact_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-CP-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled",
    "Policy Description": "The type of encryption key When creating or updating a pipeline, the value must be cmk(customer-managed key)",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform"
}

#
# PR-AWS-CLD-CD-001
#

default deploy_compute_platform = true

deploy_compute_platform = false {
    # lower(resource.Type) == "aws::codedeploy::application"
    applicationsInfo := input.applicationsInfo[_]
    not applicationsInfo.computePlatform
}

deploy_compute_platform = false {
    # lower(resource.Type) == "aws::codedeploy::application"
    applicationsInfo := input.applicationsInfo[_]
    lower(applicationsInfo.computePlatform) != "ecs"
    lower(applicationsInfo.computePlatform) != "lambda"
}

deploy_compute_platform_err = "AWS CodeDeploy application compute platform must be ECS or Lambda" {
    not deploy_compute_platform
}

deploy_compute_platform_metadata := {
    "Policy Code": "PR-AWS-CLD-CD-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CodeDeploy application compute platform must be ECS or Lambda",
    "Policy Description": "AWS CodeDeploy application compute platform must be ECS or Lambda",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform"
}
