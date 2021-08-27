package rule

#
# PR-AWS-0263-CFR
#

default aws_acm_certificate_tags = null

aws_issue["aws_acm_certificate_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    not resource.Properties.Tags
}

aws_issue["aws_acm_certificate_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    count(resource.Properties.Tags) == 0
}

aws_acm_certificate_tags {
    lower(input.Resources[i].Type) == "aws::certificatemanager::certificate"
    not aws_issue["aws_acm_certificate_tags"]
}

aws_acm_certificate_tags = false {
    aws_issue["aws_acm_certificate_tags"]
}

aws_acm_certificate_tags_err = "Ensure that Amazon Certificate Manager has an associated tag" {
    aws_issue["aws_acm_certificate_tags"]
}

aws_acm_certificate_tags_metadata := {
    "Policy Code": "PR-AWS-0263-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Amazon Certificate Manager has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html"
}

#
# PR-AWS-0264-CFR
#

default aws_acmpca_certificate_authority_tags = null

aws_issue["aws_acmpca_certificate_authority_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::acmpca::certificateauthority"
    not resource.Properties.Tags
}

aws_issue["aws_acmpca_certificate_authority_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::acmpca::certificateauthority"
    count(resource.Properties.Tags) == 0
}

aws_acmpca_certificate_authority_tags {
    lower(input.Resources[i].Type) == "aws::acmpca::certificateauthority"
    not aws_issue["aws_acmpca_certificate_authority_tags"]
}

aws_acmpca_certificate_authority_tags = false {
    aws_issue["aws_acmpca_certificate_authority_tags"]
}

aws_acmpca_certificate_authority_tags_err = "Ensure that AWS Certificate Manager Private Certificate Authorities has an associated tag" {
    aws_issue["aws_acmpca_certificate_authority_tags"]
}

aws_acmpca_certificate_authority_tags_metadata := {
    "Policy Code": "PR-AWS-0264-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that AWS Certificate Manager Private Certificate Authorities has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-acmpca-certificateauthority.html"
}

#
# PR-AWS-0265-CFR
#

default aws_api_gateway_rest_api_tags = null

aws_issue["aws_api_gateway_rest_api_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::restapi"
    not resource.Properties.Tags
}

aws_issue["aws_api_gateway_rest_api_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::restapi"
    count(resource.Properties.Tags) == 0
}

aws_api_gateway_rest_api_tags {
    lower(input.Resources[i].Type) == "aws::apigateway::restapi"
    not aws_issue["aws_api_gateway_rest_api_tags"]
}

aws_api_gateway_rest_api_tags = false {
    aws_issue["aws_api_gateway_rest_api_tags"]
}

aws_api_gateway_rest_api_tags_err = "Ensure that API Gateway REST API has an associated tag" {
    aws_issue["aws_api_gateway_rest_api_tags"]
}

aws_api_gateway_rest_api_tags_metadata := {
    "Policy Code": "PR-AWS-0265-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that API Gateway REST API has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-restapi.html"
}

#
# PR-AWS-0266-CFR
#

default aws_accessanalyzer_analyzer_tags = null

aws_issue["aws_accessanalyzer_analyzer_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::accessanalyzer::analyzer"
    not resource.Properties.Tags
}

aws_issue["aws_accessanalyzer_analyzer_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::accessanalyzer::analyzer"
    count(resource.Properties.Tags) == 0
}

aws_accessanalyzer_analyzer_tags {
    lower(input.Resources[i].Type) == "aws::accessanalyzer::analyzer"
    not aws_issue["aws_accessanalyzer_analyzer_tags"]
}

aws_accessanalyzer_analyzer_tags = false {
    aws_issue["aws_accessanalyzer_analyzer_tags"]
}

aws_accessanalyzer_analyzer_tags_err = "Ensure that Access Analyzer Analyzer has an associated tag" {
    aws_issue["aws_accessanalyzer_analyzer_tags"]
}

aws_accessanalyzer_analyzer_tags_metadata := {
    "Policy Code": "PR-AWS-0266-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Access Analyzer Analyzer has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-accessanalyzer-analyzer.html"
}

#
# PR-AWS-0267-CFR
#

default aws_amplify_app_tags = null

aws_issue["aws_amplify_app_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amplify::app"
    not resource.Properties.Tags
}

aws_issue["aws_amplify_app_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::amplify::app"
    count(resource.Properties.Tags) == 0
}

aws_amplify_app_tags {
    lower(input.Resources[i].Type) == "aws::amplify::app"
    not aws_issue["aws_amplify_app_tags"]
}

aws_amplify_app_tags = false {
    aws_issue["aws_amplify_app_tags"]
}

aws_amplify_app_tags_err = "Ensure that Amplify App has an associated tag" {
    aws_issue["aws_amplify_app_tags"]
}

aws_amplify_app_tags_metadata := {
    "Policy Code": "PR-AWS-0267-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Amplify App has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-app.html"
}

#
# PR-AWS-0268-CFR
#

default aws_apprunner_service_tags = null

aws_issue["aws_apprunner_service_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apprunner::service"
    not resource.Properties.Tags
}

aws_issue["aws_apprunner_service_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apprunner::service"
    count(resource.Properties.Tags) == 0
}

aws_apprunner_service_tags {
    lower(input.Resources[i].Type) == "aws::apprunner::service"
    not aws_issue["aws_apprunner_service_tags"]
}

aws_apprunner_service_tags = false {
    aws_issue["aws_apprunner_service_tags"]
}

aws_apprunner_service_tags_err = "Ensure that App Runner Service has an associated tag" {
    aws_issue["aws_apprunner_service_tags"]
}

aws_apprunner_service_tags_metadata := {
    "Policy Code": "PR-AWS-0268-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that App Runner Service has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apprunner-service.html"
}

#
# PR-AWS-0269-CFR
#

default aws_appconfig_deployment_tags = null

aws_issue["aws_appconfig_deployment_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::appconfig::deployment"
    not resource.Properties.Tags
}

aws_issue["aws_appconfig_deployment_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::appconfig::deployment"
    count(resource.Properties.Tags) == 0
}

aws_appconfig_deployment_tags {
    lower(input.Resources[i].Type) == "aws::appconfig::deployment"
    not aws_issue["aws_appconfig_deployment_tags"]
}

aws_appconfig_deployment_tags = false {
    aws_issue["aws_appconfig_deployment_tags"]
}

aws_appconfig_deployment_tags_err = "Ensure that AppConfig Deployment has an associated tag" {
    aws_issue["aws_appconfig_deployment_tags"]
}

aws_appconfig_deployment_tags_metadata := {
    "Policy Code": "PR-AWS-0269-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that AppConfig Deployment has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appconfig-deployment.html"
}

#
# PR-AWS-0270-CFR
#

default aws_cloudfront_distribution_tags = null

aws_issue["aws_cloudfront_distribution_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.Tags
}

aws_issue["aws_cloudfront_distribution_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.Tags) == 0
}

aws_cloudfront_distribution_tags {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["aws_cloudfront_distribution_tags"]
}

aws_cloudfront_distribution_tags = false {
    aws_issue["aws_cloudfront_distribution_tags"]
}

aws_cloudfront_distribution_tags_err = "Ensure that Amazon CloudFront web distribution has an associated tag" {
    aws_issue["aws_cloudfront_distribution_tags"]
}

aws_cloudfront_distribution_tags_metadata := {
    "Policy Code": "PR-AWS-0270-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Amazon CloudFront web distribution has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0271-CFR
#

default aws_cloudtrail_tags = null

aws_issue["aws_cloudtrail_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    not resource.Properties.Tags
}

aws_issue["aws_cloudtrail_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudtrail::trail"
    count(resource.Properties.Tags) == 0
}

aws_cloudtrail_tags {
    lower(input.Resources[i].Type) == "aws::cloudtrail::trail"
    not aws_issue["aws_cloudtrail_tags"]
}

aws_cloudtrail_tags = false {
    aws_issue["aws_cloudtrail_tags"]
}

aws_cloudtrail_tags_err = "Ensure that CloudTrail resource has an associated tag" {
    aws_issue["aws_cloudtrail_tags"]
}

aws_cloudtrail_tags_metadata := {
    "Policy Code": "PR-AWS-0271-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that CloudTrail resource has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html"
}

#
# PR-AWS-0272-CFR
#

default aws_codedeploy_app_tags = null

aws_issue["aws_codedeploy_app_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codedeploy::application"
    not resource.Properties.Tags
}

aws_issue["aws_codedeploy_app_tags"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::codedeploy::application"
    count(resource.Properties.Tags) == 0
}

aws_codedeploy_app_tags {
    lower(input.Resources[i].Type) == "aws::codedeploy::application"
    not aws_issue["aws_codedeploy_app_tags"]
}

aws_codedeploy_app_tags = false {
    aws_issue["aws_codedeploy_app_tags"]
}

aws_codedeploy_app_tags_err = "Ensure that CodeDeploy application has an associated tag" {
    aws_issue["aws_codedeploy_app_tags"]
}

aws_codedeploy_app_tags_metadata := {
    "Policy Code": "PR-AWS-0272-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that CodeDeploy application has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html"
}

#
# PR-AWS-0273-CFR
#

default aws_codepipeline_tags = null

aws_issue["aws_codepipeline_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::codepipeline::pipeline"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_codepipeline_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::codepipeline::pipeline"
    not resource.Properties.Tags
}

aws_codepipeline_tags {
    lower(input.Resources[i].Type) == "aws::codepipeline::pipeline"
    not aws_issue["aws_codepipeline_tags"]
}

aws_codepipeline_tags = false {
    aws_issue["aws_codepipeline_tags"]
}

aws_codepipeline_tags_err = "Ensure that CodePipeline has an associated tag" {
    aws_issue["aws_codepipeline_tags"]
}

aws_codepipeline_tags_metadata := {
    "Policy Code": "PR-AWS-0273-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that CodePipeline has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codepipeline-pipeline.html"
}

#
# PR-AWS-0274-CFR
#

default aws_dynamodb_table_tags = null

aws_issue["aws_dynamodb_table_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::dynamodb::table"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_dynamodb_table_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::dynamodb::table"
    not resource.Properties.Tags
}

aws_dynamodb_table_tags {
    lower(input.Resources[i].Type) == "aws::dynamodb::table"
    not aws_issue["aws_dynamodb_table_tags"]
}

aws_dynamodb_table_tags = false {
    aws_issue["aws_dynamodb_table_tags"]
}

aws_dynamodb_table_tags_err = "Ensure that DynamoDB has an associated tag" {
    aws_issue["aws_dynamodb_table_tags"]
}

aws_dynamodb_table_tags_metadata := {
    "Policy Code": "PR-AWS-0274-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that DynamoDB has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html"
}

#
# PR-AWS-0275-CFR
#

default aws_dax_cluster_tags = null

aws_issue["aws_dax_cluster_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::dax::cluster"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_dax_cluster_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::dax::cluster"
    not resource.Properties.Tags
}

aws_dax_cluster_tags {
    lower(input.Resources[i].Type) == "aws::dax::cluster"
    not aws_issue["aws_dax_cluster_tags"]
}

aws_dax_cluster_tags = false {
    aws_issue["aws_dax_cluster_tags"]
}

aws_dax_cluster_tags_err = "Ensure that DAX Cluster has an associated tag" {
    aws_issue["aws_dax_cluster_tags"]
}

aws_dax_cluster_tags_metadata := {
    "Policy Code": "PR-AWS-0275-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that DAX Cluster has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html"
}

#
# PR-AWS-0276-CFR
#

default aws_instance_tags = null

aws_issue["aws_instance_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::ec2::instance"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_instance_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::ec2::instance"
    not resource.Properties.Tags
}

aws_instance_tags {
    lower(input.Resources[i].Type) == "aws::ec2::instance"
    not aws_issue["aws_instance_tags"]
}

aws_instance_tags = false {
    aws_issue["aws_instance_tags"]
}

aws_instance_tags_err = "Ensure that EC2 instance has an associated tag" {
    aws_issue["aws_instance_tags"]
}

aws_instance_tags_metadata := {
    "Policy Code": "PR-AWS-0276-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that EC2 instance has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html"
}

#
# PR-AWS-0277-CFR
#

default aws_ebs_volume_tags = null

aws_issue["aws_ebs_volume_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::ec2::volume"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_ebs_volume_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::ec2::volume"
    not resource.Properties.Tags
}

aws_ebs_volume_tags {
    lower(input.Resources[i].Type) == "aws::ec2::volume"
    not aws_issue["aws_ebs_volume_tags"]
}

aws_ebs_volume_tags = false {
    aws_issue["aws_ebs_volume_tags"]
}

aws_ebs_volume_tags_err = "Ensure that EBS volume has an associated tag" {
    aws_issue["aws_ebs_volume_tags"]
}

aws_ebs_volume_tags_metadata := {
    "Policy Code": "PR-AWS-0277-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that EBS volume has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html"
}

#
# PR-AWS-0278-CFR
#

default aws_ecr_repository_tags = null

aws_issue["aws_ecr_repository_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::ecr::repository"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_ecr_repository_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::ecr::repository"
    not resource.Properties.Tags
}

aws_ecr_repository_tags {
    lower(input.Resources[i].Type) == "aws::ecr::repository"
    not aws_issue["aws_ecr_repository_tags"]
}

aws_ecr_repository_tags = false {
    aws_issue["aws_ecr_repository_tags"]
}

aws_ecr_repository_tags_err = "Ensure that Elastic Container Registry Repository has an associated tag" {
    aws_issue["aws_ecr_repository_tags"]
}

aws_ecr_repository_tags_metadata := {
    "Policy Code": "PR-AWS-0278-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Elastic Container Registry Repository has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html"
}

#
# PR-AWS-0279-CFR
#

default aws_ecs_cluster_tags = null

aws_issue["aws_ecs_cluster_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::ecs::cluster"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_ecs_cluster_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::ecs::cluster"
    not resource.Properties.Tags
}

aws_ecs_cluster_tags {
    lower(input.Resources[i].Type) == "aws::ecs::cluster"
    not aws_issue["aws_ecs_cluster_tags"]
}

aws_ecs_cluster_tags = false {
    aws_issue["aws_ecs_cluster_tags"]
}

aws_ecs_cluster_tags_err = "Ensure that ECS cluster has an associated tag" {
    aws_issue["aws_ecs_cluster_tags"]
}

aws_ecs_cluster_tags_metadata := {
    "Policy Code": "PR-AWS-0279-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that ECS cluster has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-cluster.html"
}


#
# PR-AWS-0280-CFR
#

default aws_ecs_task_definition_tags = null

aws_issue["aws_ecs_task_definition_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::ecs::taskdefinition"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_ecs_task_definition_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::ecs::taskdefinition"
    not resource.Properties.Tags
}

aws_ecs_task_definition_tags {
    lower(input.Resources[i].Type) == "aws::ecs::taskdefinition"
    not aws_issue["aws_ecs_task_definition_tags"]
}

aws_ecs_task_definition_tags = false {
    aws_issue["aws_ecs_task_definition_tags"]
}

aws_ecs_task_definition_tags_err = "Ensure that ECS task definition has an associated tag" {
    aws_issue["aws_ecs_task_definition_tags"]
}

aws_ecs_task_definition_tags_metadata := {
    "Policy Code": "PR-AWS-0280-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that ECS task definition has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html"
}

#
# PR-AWS-0281-CFR
#

default aws_ecs_service_tags = null

aws_issue["aws_ecs_service_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws::ecs::service"
    count(resource.properties.tags) == 0
}

aws_issue["aws_ecs_service_tags"] {
    resource := input.resources[i]
    lower(resource.type) == "aws::ecs::service"
    not resource.properties.tags
}

aws_ecs_service_tags {
    lower(input.resources[i].type) == "aws::ecs::service"
    not aws_issue["aws_ecs_service_tags"]
}

aws_ecs_service_tags = false {
    aws_issue["aws_ecs_service_tags"]
}

aws_ecs_service_tags_err = "Ensure that ECS service has an associated tag" {
    aws_issue["aws_ecs_service_tags"]
}

aws_ecs_service_tags_metadata := {
    "Policy Code": "PR-AWS-0281-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that ECS service has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html"
}

#
# PR-AWS-0282-CFR
#

default aws_efs_file_system_tags = null

aws_issue["aws_efs_file_system_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::efs::filesystem"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_efs_file_system_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::efs::filesystem"
    not resource.Properties.Tags
}

aws_efs_file_system_tags {
    lower(input.Resources[i].Type) == "aws::efs::filesystem"
    not aws_issue["aws_efs_file_system_tags"]
}

aws_efs_file_system_tags = false {
    aws_issue["aws_efs_file_system_tags"]
}

aws_efs_file_system_tags_err = "Ensure that Elastic File System (EFS) File System resource has an associated tag" {
    aws_issue["aws_efs_file_system_tags"]
}

aws_efs_file_system_tags_metadata := {
    "Policy Code": "PR-AWS-0282-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Elastic File System (EFS) File System resource has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html"
}


#
# PR-AWS-0283-CFR
#

default aws_eks_cluster_tags = null

aws_issue["aws_eks_cluster_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::eks::cluster"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_eks_cluster_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::eks::cluster"
    not resource.Properties.Tags
}

aws_eks_cluster_tags {
    lower(input.Resources[i].Type) == "aws::eks::cluster"
    not aws_issue["aws_eks_cluster_tags"]
}

aws_eks_cluster_tags = false {
    aws_issue["aws_eks_cluster_tags"]
}

aws_eks_cluster_tags_err = "Ensure that EKS Cluster has an associated tag" {
    aws_issue["aws_eks_cluster_tags"]
}

aws_eks_cluster_tags_metadata := {
    "Policy Code": "PR-AWS-0283-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that EKS Cluster has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html"
}

#
# PR-AWS-0284-CFR
#

default aws_elasticache_cluster_tags = null

aws_issue["aws_elasticache_cluster_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::elasticache::cachecluster"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_elasticache_cluster_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::elasticache::cachecluster"
    not resource.Properties.Tags
}

aws_elasticache_cluster_tags {
    lower(input.Resources[i].Type) == "aws::elasticache::cachecluster"
    not aws_issue["aws_elasticache_cluster_tags"]
}

aws_elasticache_cluster_tags = false {
    aws_issue["aws_elasticache_cluster_tags"]
}

aws_elasticache_cluster_tags_err = "Ensure that Elasticache Cluster has an associated tag" {
    aws_issue["aws_elasticache_cluster_tags"]
}

aws_elasticache_cluster_tags_metadata := {
    "Policy Code": "PR-AWS-0284-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Elasticache Cluster has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticache-cache-cluster.html"
}


#
# PR-AWS-0285-CFR
#

default aws_elb_tags = null

aws_issue["aws_elb_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_elb_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.Tags
}

aws_elb_tags {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancing::loadbalancer"
    not aws_issue["aws_elb_tags"]
}

aws_elb_tags = false {
    aws_issue["aws_elb_tags"]
}

aws_elb_tags_err = "Ensure that Elastic Load Balancer has an associated tag" {
    aws_issue["aws_elb_tags"]
}

aws_elb_tags_metadata := {
    "Policy Code": "PR-AWS-0285-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Elastic Load Balancer has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}


#
# PR-AWS-0286-CFR
#

default aws_emr_cluster_tags = null

aws_issue["aws_emr_cluster_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::emr::cluster"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_emr_cluster_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::emr::cluster"
    not resource.Properties.Tags
}

aws_emr_cluster_tags {
    lower(input.Resources[i].Type) == "aws::emr::cluster"
    not aws_issue["aws_emr_cluster_tags"]
}

aws_emr_cluster_tags = false {
    aws_issue["aws_emr_cluster_tags"]
}

aws_emr_cluster_tags_err = "Ensure that Elastic MapReduce Cluster has an associated tag" {
    aws_issue["aws_emr_cluster_tags"]
}

aws_emr_cluster_tags_metadata := {
    "Policy Code": "PR-AWS-0286-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Elastic MapReduce Cluster has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html"
}


#
# PR-AWS-0287-CFR
#

default aws_elasticsearch_domain_tags = null

aws_issue["aws_elasticsearch_domain_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::elasticsearch::domain"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_elasticsearch_domain_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::elasticsearch::domain"
    not resource.Properties.Tags
}

aws_elasticsearch_domain_tags {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["aws_elasticsearch_domain_tags"]
}

aws_elasticsearch_domain_tags = false {
    aws_issue["aws_elasticsearch_domain_tags"]
}

aws_elasticsearch_domain_tags_err = "Ensure that Elasticsearch Domain has an associated tag" {
    aws_issue["aws_elasticsearch_domain_tags"]
}

aws_elasticsearch_domain_tags_metadata := {
    "Policy Code": "PR-AWS-0287-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Elasticsearch Domain has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-0288-CFR
#

default aws_kms_key_tags = null

aws_issue["aws_kms_key_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::kms::key"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_kms_key_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::kms::key"
    not resource.Properties.Tags
}

aws_kms_key_tags {
    lower(input.Resources[i].Type) == "aws::kms::key"
    not aws_issue["aws_kms_key_tags"]
}

aws_kms_key_tags = false {
    aws_issue["aws_kms_key_tags"]
}

aws_kms_key_tags_err = "Ensure that KMS single-Region customer master key (CMK) has an associated tag" {
    aws_issue["aws_kms_key_tags"]
}

aws_kms_key_tags_metadata := {
    "Policy Code": "PR-AWS-0288-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that KMS single-Region customer master key (CMK) has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html"
}

#
# PR-AWS-0289-CFR
#

default aws_kinesis_stream_tags = null

aws_issue["aws_kinesis_stream_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::kinesis::stream"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_kinesis_stream_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::kinesis::stream"
    not resource.Properties.Tags
}

aws_kinesis_stream_tags {
    lower(input.Resources[i].Type) == "aws::kinesis::stream"
    not aws_issue["aws_kinesis_stream_tags"]
}

aws_kinesis_stream_tags = false {
    aws_issue["aws_kinesis_stream_tags"]
}

aws_kinesis_stream_tags_err = "Ensure that Kinesis Stream has an associated tag" {
    aws_issue["aws_kinesis_stream_tags"]
}

aws_kinesis_stream_tags_metadata := {
    "Policy Code": "PR-AWS-0289-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Kinesis Stream has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html"
}


#
# PR-AWS-0290-CFR
#

default aws_lambda_function_tags = null

aws_issue["aws_lambda_function_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::lambda::function"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_lambda_function_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::lambda::function"
    not resource.Properties.Tags
}

aws_lambda_function_tags {
    lower(input.Resources[i].Type) == "aws::lambda::function"
    not aws_issue["aws_lambda_function_tags"]
}

aws_lambda_function_tags = false {
    aws_issue["aws_lambda_function_tags"]
}

aws_lambda_function_tags_err = "Ensure that Lambda Function has an associated tag" {
    aws_issue["aws_lambda_function_tags"]
}

aws_lambda_function_tags_metadata := {
    "Policy Code": "PR-AWS-0290-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Lambda Function has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}

#
# PR-AWS-0291-CFR
#

default aws_mq_broker_tags = null

aws_issue["aws_mq_broker_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::amazonmq::broker"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_mq_broker_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::amazonmq::broker"
    not resource.Properties.Tags
}

aws_mq_broker_tags {
    lower(input.Resources[i].Type) == "aws::amazonmq::broker"
    not aws_issue["aws_mq_broker_tags"]
}

aws_mq_broker_tags = false {
    aws_issue["aws_mq_broker_tags"]
}

aws_mq_broker_tags_err = "Ensure that Amazon MQ broker has an associated tag" {
    aws_issue["aws_mq_broker_tags"]
}

aws_mq_broker_tags_metadata := {
    "Policy Code": "PR-AWS-0291-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Amazon MQ broker has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amazonmq-broker.html"
}

#
# PR-AWS-0292-CFR
#

default aws_qldb_ledger_tags = null

aws_issue["aws_qldb_ledger_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::qldb::ledger"
    count(resource.Properties.Tags) == 0
}

aws_issue["aws_qldb_ledger_tags"] {
    resource := input.Resources[i]
    lower(resource.type) == "aws::qldb::ledger"
    not resource.Properties.Tags
}

aws_qldb_ledger_tags {
    lower(input.Resources[i].Type) == "aws::qldb::ledger"
    not aws_issue["aws_qldb_ledger_tags"]
}

aws_qldb_ledger_tags = false {
    aws_issue["aws_qldb_ledger_tags"]
}

aws_qldb_ledger_tags_err = "Ensure that AWS Quantum Ledger Database has an associated tag" {
    aws_issue["aws_qldb_ledger_tags"]
}

aws_qldb_ledger_tags_metadata := {
    "Policy Code": "PR-AWS-0292-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that AWS Quantum Ledger Database has an associated tag",
    "Policy Description": "The Tag type enables you to specify a key-value pair that can be used to store information about an AWS CloudFormation stack. we recommend to add tags in a resource.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html"
}
