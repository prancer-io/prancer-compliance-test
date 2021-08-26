package rule

#
# PR-AWS-0263-TRF
#

default aws_acm_certificate_tags = null

aws_issue["aws_acm_certificate_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_acm_certificate"
    count(resource.properties.tags) == 0
}

aws_issue["aws_acm_certificate_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_acm_certificate"
    not resource.properties.tags
}

aws_acm_certificate_tags {
    lower(input.resources[i].type) == "aws_acm_certificate"
    not aws_issue["aws_acm_certificate_tags"]
}

aws_acm_certificate_tags = false {
    aws_issue["aws_acm_certificate_tags"]
}

aws_acm_certificate_tags_err = "Ensure that Amazon Certificate Manager has an associated tag" {
    aws_issue["aws_acm_certificate_tags"]
}

aws_acm_certificate_tags_metadata := {
    "Policy Code": "PR-AWS-0263-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Amazon Certificate Manager has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-acmpca-certificateauthority.html"
}


#
# PR-AWS-0264-TRF
#

default aws_acmpca_certificate_authority_tags = null

aws_issue["aws_acmpca_certificate_authority_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_acmpca_certificate_authority"
    count(resource.properties.tags) == 0
}

aws_issue["aws_acmpca_certificate_authority_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_acmpca_certificate_authority"
    not resource.properties.tags
}

aws_acmpca_certificate_authority_tags {
    lower(input.resources[i].type) == "aws_acmpca_certificate_authority"
    not aws_issue["aws_acmpca_certificate_authority_tags"]
}

aws_acmpca_certificate_authority_tags = false {
    aws_issue["aws_acmpca_certificate_authority_tags"]
}

aws_acmpca_certificate_authority_tags_err = "Ensure that AWS Certificate Manager Private Certificate Authorities has an associated tag" {
    aws_issue["aws_acmpca_certificate_authority_tags"]
}

aws_acmpca_certificate_authority_tags_metadata := {
    "Policy Code": "PR-AWS-0264-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that AWS Certificate Manager Private Certificate Authorities has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/acmpca_certificate_authority"
}


#
# PR-AWS-0265-TRF
#

default aws_api_gateway_rest_api_tags = null

aws_issue["aws_api_gateway_rest_api_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    count(resource.properties.tags) == 0
}

aws_issue["aws_api_gateway_rest_api_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_api_gateway_rest_api"
    not resource.properties.tags
}

aws_api_gateway_rest_api_tags {
    lower(input.resources[i].type) == "aws_api_gateway_rest_api"
    not aws_issue["aws_api_gateway_rest_api_tags"]
}

aws_api_gateway_rest_api_tags = false {
    aws_issue["aws_api_gateway_rest_api_tags"]
}

aws_api_gateway_rest_api_tags_err = "Ensure that API Gateway REST API has an associated tag" {
    aws_issue["aws_api_gateway_rest_api_tags"]
}

aws_api_gateway_rest_api_tags_metadata := {
    "Policy Code": "PR-AWS-0265-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that API Gateway REST API has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api"
}


#
# PR-AWS-0266-TRF
#

default aws_accessanalyzer_analyzer_tags = null

aws_issue["aws_accessanalyzer_analyzer_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_accessanalyzer_analyzer"
    count(resource.properties.tags) == 0
}

aws_issue["aws_accessanalyzer_analyzer_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_accessanalyzer_analyzer"
    not resource.properties.tags
}

aws_accessanalyzer_analyzer_tags {
    lower(input.resources[i].type) == "aws_accessanalyzer_analyzer"
    not aws_issue["aws_accessanalyzer_analyzer_tags"]
}

aws_accessanalyzer_analyzer_tags = false {
    aws_issue["aws_accessanalyzer_analyzer_tags"]
}

aws_accessanalyzer_analyzer_tags_err = "Ensure that Access Analyzer Analyzer has an associated tag" {
    aws_issue["aws_accessanalyzer_analyzer_tags"]
}

aws_accessanalyzer_analyzer_tags_metadata := {
    "Policy Code": "PR-AWS-0266-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Access Analyzer Analyzer has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/accessanalyzer_analyzer"
}


#
# PR-AWS-0267-TRF
#

default aws_amplify_app_tags = null

aws_issue["aws_amplify_app_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_amplify_app"
    count(resource.properties.tags) == 0
}

aws_issue["aws_amplify_app_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_amplify_app"
    not resource.properties.tags
}

aws_amplify_app_tags {
    lower(input.resources[i].type) == "aws_amplify_app"
    not aws_issue["aws_amplify_app_tags"]
}

aws_amplify_app_tags = false {
    aws_issue["aws_amplify_app_tags"]
}

aws_amplify_app_tags_err = "Ensure that Amplify App has an associated tag" {
    aws_issue["aws_amplify_app_tags"]
}

aws_amplify_app_tags_metadata := {
    "Policy Code": "PR-AWS-0267-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Amplify App has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/amplify_app"
}

#
# PR-AWS-0268-TRF
#

default aws_apprunner_auto_scaling_configuration_version_tags = null

aws_issue["aws_apprunner_auto_scaling_configuration_version_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_apprunner_auto_scaling_configuration_version"
    count(resource.properties.tags) == 0
}

aws_issue["aws_apprunner_auto_scaling_configuration_version_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_apprunner_auto_scaling_configuration_version"
    not resource.properties.tags
}

aws_apprunner_auto_scaling_configuration_version_tags {
    lower(input.resources[i].type) == "aws_apprunner_auto_scaling_configuration_version"
    not aws_issue["aws_apprunner_auto_scaling_configuration_version_tags"]
}

aws_apprunner_auto_scaling_configuration_version_tags = false {
    aws_issue["aws_apprunner_auto_scaling_configuration_version_tags"]
}

aws_apprunner_auto_scaling_configuration_version_tags_err = "Ensure that App Runner AutoScaling Configuration Version has an associated tag" {
    aws_issue["aws_apprunner_auto_scaling_configuration_version_tags"]
}

aws_apprunner_auto_scaling_configuration_version_tags_metadata := {
    "Policy Code": "PR-AWS-0268-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that App Runner AutoScaling Configuration Version has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/apprunner_auto_scaling_configuration_version"
}

#
# PR-AWS-0269-TRF
#

default aws_appconfig_deployment_tags = null

aws_issue["aws_appconfig_deployment_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_appconfig_deployment"
    count(resource.properties.tags) == 0
}

aws_issue["aws_appconfig_deployment_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_appconfig_deployment"
    not resource.properties.tags
}

aws_appconfig_deployment_tags {
    lower(input.resources[i].type) == "aws_appconfig_deployment"
    not aws_issue["aws_appconfig_deployment_tags"]
}

aws_appconfig_deployment_tags = false {
    aws_issue["aws_appconfig_deployment_tags"]
}

aws_appconfig_deployment_tags_err = "Ensure that AppConfig Deployment has an associated tag" {
    aws_issue["aws_appconfig_deployment_tags"]
}

aws_appconfig_deployment_tags_metadata := {
    "Policy Code": "PR-AWS-0269-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that AppConfig Deployment has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/appconfig_deployment"
}

#
# PR-AWS-0270-TRF
#

default aws_cloudfront_distribution_tags = null

aws_issue["aws_cloudfront_distribution_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.tags) == 0
}

aws_issue["aws_cloudfront_distribution_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.tags
}

aws_cloudfront_distribution_tags {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
    not aws_issue["aws_cloudfront_distribution_tags"]
}

aws_cloudfront_distribution_tags = false {
    aws_issue["aws_cloudfront_distribution_tags"]
}

aws_cloudfront_distribution_tags_err = "Ensure that Amazon CloudFront web distribution has an associated tag" {
    aws_issue["aws_cloudfront_distribution_tags"]
}

aws_cloudfront_distribution_tags_metadata := {
    "Policy Code": "PR-AWS-0270-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Amazon CloudFront web distribution has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution"
}

#
# PR-AWS-0271-TRF
#

default aws_cloudtrail_tags = null

aws_issue["aws_cloudtrail_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudtrail"
    count(resource.properties.tags) == 0
}

aws_issue["aws_cloudtrail_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudtrail"
    not resource.properties.tags
}

aws_cloudtrail_tags {
    lower(input.resources[i].type) == "aws_cloudtrail"
    not aws_issue["aws_cloudtrail_tags"]
}

aws_cloudtrail_tags = false {
    aws_issue["aws_cloudtrail_tags"]
}

aws_cloudtrail_tags_err = "Ensure that CloudTrail resource has an associated tag" {
    aws_issue["aws_cloudtrail_tags"]
}

aws_cloudtrail_tags_metadata := {
    "Policy Code": "PR-AWS-0271-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that CloudTrail resource has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution"
}

#
# PR-AWS-0272-TRF
#

default aws_codedeploy_app_tags = null

aws_issue["aws_codedeploy_app_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codedeploy_app"
    count(resource.properties.tags) == 0
}

aws_issue["aws_codedeploy_app_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codedeploy_app"
    not resource.properties.tags
}

aws_codedeploy_app_tags {
    lower(input.resources[i].type) == "aws_codedeploy_app"
    not aws_issue["aws_codedeploy_app_tags"]
}

aws_codedeploy_app_tags = false {
    aws_issue["aws_codedeploy_app_tags"]
}

aws_codedeploy_app_tags_err = "Ensure that CodeDeploy application has an associated tag" {
    aws_issue["aws_codedeploy_app_tags"]
}

aws_codedeploy_app_tags_metadata := {
    "Policy Code": "PR-AWS-0272-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that CodeDeploy application has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codedeploy_app"
}

#
# PR-AWS-0273-TRF
#

default aws_codepipeline_tags = null

aws_issue["aws_codepipeline_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codepipeline"
    count(resource.properties.tags) == 0
}

aws_issue["aws_codepipeline_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_codepipeline"
    not resource.properties.tags
}

aws_codepipeline_tags {
    lower(input.resources[i].type) == "aws_codepipeline"
    not aws_issue["aws_codepipeline_tags"]
}

aws_codepipeline_tags = false {
    aws_issue["aws_codepipeline_tags"]
}

aws_codepipeline_tags_err = "Ensure that CodePipeline has an associated tag" {
    aws_issue["aws_codepipeline_tags"]
}

aws_codepipeline_tags_metadata := {
    "Policy Code": "PR-AWS-0273-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that CodePipeline has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codepipeline"
}

#
# PR-AWS-0274-TRF
#

default aws_dynamodb_table_tags = null

aws_issue["aws_dynamodb_table_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dynamodb_table"
    count(resource.properties.tags) == 0
}

aws_issue["aws_dynamodb_table_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dynamodb_table"
    not resource.properties.tags
}

aws_dynamodb_table_tags {
    lower(input.resources[i].type) == "aws_dynamodb_table"
    not aws_issue["aws_dynamodb_table_tags"]
}

aws_dynamodb_table_tags = false {
    aws_issue["aws_dynamodb_table_tags"]
}

aws_dynamodb_table_tags_err = "Ensure that DynamoDB has an associated tag" {
    aws_issue["aws_dynamodb_table_tags"]
}

aws_dynamodb_table_tags_metadata := {
    "Policy Code": "PR-AWS-0274-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that DynamoDB has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table"
}

#
# PR-AWS-0275-TRF
#

default aws_dax_cluster_tags = null

aws_issue["aws_dax_cluster_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dax_cluster"
    count(resource.properties.tags) == 0
}

aws_issue["aws_dax_cluster_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dax_cluster"
    not resource.properties.tags
}

aws_dax_cluster_tags {
    lower(input.resources[i].type) == "aws_dax_cluster"
    not aws_issue["aws_dax_cluster_tags"]
}

aws_dax_cluster_tags = false {
    aws_issue["aws_dax_cluster_tags"]
}

aws_dax_cluster_tags_err = "Ensure that DAX Cluster has an associated tag" {
    aws_issue["aws_dax_cluster_tags"]
}

aws_dax_cluster_tags_metadata := {
    "Policy Code": "PR-AWS-0275-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that DAX Cluster has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dax_cluster"
}

#
# PR-AWS-0276-TRF
#

default aws_instance_tags = null

aws_issue["aws_instance_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    count(resource.properties.tags) == 0
}

aws_issue["aws_instance_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_instance"
    not resource.properties.tags
}

aws_instance_tags {
    lower(input.resources[i].type) == "aws_instance"
    not aws_issue["aws_instance_tags"]
}

aws_instance_tags = false {
    aws_issue["aws_instance_tags"]
}

aws_instance_tags_err = "Ensure that EC2 instance has an associated tag" {
    aws_issue["aws_instance_tags"]
}

aws_instance_tags_metadata := {
    "Policy Code": "PR-AWS-0276-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that EC2 instance has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance"
}

#
# PR-AWS-0277-TRF
#

default aws_ebs_volume_tags = null

aws_issue["aws_ebs_volume_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ebs_volume"
    count(resource.properties.tags) == 0
}

aws_issue["aws_ebs_volume_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ebs_volume"
    not resource.properties.tags
}

aws_ebs_volume_tags {
    lower(input.resources[i].type) == "aws_ebs_volume"
    not aws_issue["aws_ebs_volume_tags"]
}

aws_ebs_volume_tags = false {
    aws_issue["aws_ebs_volume_tags"]
}

aws_ebs_volume_tags_err = "Ensure that EBS volume has an associated tag" {
    aws_issue["aws_ebs_volume_tags"]
}

aws_ebs_volume_tags_metadata := {
    "Policy Code": "PR-AWS-0277-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that EBS volume has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume"
}

#
# PR-AWS-0278-TRF
#

default aws_ecr_repository_tags = null

aws_issue["aws_ecr_repository_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    count(resource.properties.tags) == 0
}

aws_issue["aws_ecr_repository_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecr_repository"
    not resource.properties.tags
}

aws_ecr_repository_tags {
    lower(input.resources[i].type) == "aws_ecr_repository"
    not aws_issue["aws_ecr_repository_tags"]
}

aws_ecr_repository_tags = false {
    aws_issue["aws_ecr_repository_tags"]
}

aws_ecr_repository_tags_err = "Ensure that Elastic Container Registry Repository has an associated tag" {
    aws_issue["aws_ecr_repository_tags"]
}

aws_ecr_repository_tags_metadata := {
    "Policy Code": "PR-AWS-0278-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Elastic Container Registry Repository has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository"
}


#
# PR-AWS-0279-TRF
#

default aws_ecs_cluster_tags = null

aws_issue["aws_ecs_cluster_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_cluster"
    count(resource.properties.tags) == 0
}

aws_issue["aws_ecs_cluster_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_cluster"
    not resource.properties.tags
}

aws_ecs_cluster_tags {
    lower(input.resources[i].type) == "aws_ecs_cluster"
    not aws_issue["aws_ecs_cluster_tags"]
}

aws_ecs_cluster_tags = false {
    aws_issue["aws_ecs_cluster_tags"]
}

aws_ecs_cluster_tags_err = "Ensure that ECS cluster has an associated tag" {
    aws_issue["aws_ecs_cluster_tags"]
}

aws_ecs_cluster_tags_metadata := {
    "Policy Code": "PR-AWS-0279-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that ECS cluster has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_cluster"
}


#
# PR-AWS-0280-TRF
#

default aws_ecs_task_definition_tags = null

aws_issue["aws_ecs_task_definition_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    count(resource.properties.tags) == 0
}

aws_issue["aws_ecs_task_definition_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_task_definition"
    not resource.properties.tags
}

aws_ecs_task_definition_tags {
    lower(input.resources[i].type) == "aws_ecs_task_definition"
    not aws_issue["aws_ecs_task_definition_tags"]
}

aws_ecs_task_definition_tags = false {
    aws_issue["aws_ecs_task_definition_tags"]
}

aws_ecs_task_definition_tags_err = "Ensure that ECS task definition has an associated tag" {
    aws_issue["aws_ecs_task_definition_tags"]
}

aws_ecs_task_definition_tags_metadata := {
    "Policy Code": "PR-AWS-0280-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that ECS task definition has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition"
}

#
# PR-AWS-0281-TRF
#

default aws_ecs_container_definition_tags = null

aws_issue["aws_ecs_container_definition_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_container_definition"
    count(resource.properties.tags) == 0
}

aws_issue["aws_ecs_container_definition_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_ecs_container_definition"
    not resource.properties.tags
}

aws_ecs_container_definition_tags {
    lower(input.resources[i].type) == "aws_ecs_container_definition"
    not aws_issue["aws_ecs_container_definition_tags"]
}

aws_ecs_container_definition_tags = false {
    aws_issue["aws_ecs_container_definition_tags"]
}

aws_ecs_container_definition_tags_err = "Ensure that ECS container definition has an associated tag" {
    aws_issue["aws_ecs_container_definition_tags"]
}

aws_ecs_container_definition_tags_metadata := {
    "Policy Code": "PR-AWS-0281-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that ECS container definition has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ecs_container_definition"
}

#
# PR-AWS-0282-TRF
#

default aws_efs_file_system_tags = null

aws_issue["aws_efs_file_system_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    count(resource.properties.tags) == 0
}

aws_issue["aws_efs_file_system_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_efs_file_system"
    not resource.properties.tags
}

aws_efs_file_system_tags {
    lower(input.resources[i].type) == "aws_efs_file_system"
    not aws_issue["aws_efs_file_system_tags"]
}

aws_efs_file_system_tags = false {
    aws_issue["aws_efs_file_system_tags"]
}

aws_efs_file_system_tags_err = "Ensure that Elastic File System (EFS) File System resource has an associated tag" {
    aws_issue["aws_efs_file_system_tags"]
}

aws_efs_file_system_tags_metadata := {
    "Policy Code": "PR-AWS-0282-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Elastic File System (EFS) File System resource has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system"
}


#
# PR-AWS-0283-TRF
#

default aws_eks_cluster_tags = null

aws_issue["aws_eks_cluster_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    count(resource.properties.tags) == 0
}

aws_issue["aws_eks_cluster_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_eks_cluster"
    not resource.properties.tags
}

aws_eks_cluster_tags {
    lower(input.resources[i].type) == "aws_eks_cluster"
    not aws_issue["aws_eks_cluster_tags"]
}

aws_eks_cluster_tags = false {
    aws_issue["aws_eks_cluster_tags"]
}

aws_eks_cluster_tags_err = "Ensure that EKS Cluster has an associated tag" {
    aws_issue["aws_eks_cluster_tags"]
}

aws_eks_cluster_tags_metadata := {
    "Policy Code": "PR-AWS-0283-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that EKS Cluster has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster"
}
