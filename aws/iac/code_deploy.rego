package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform
#
# PR-AWS-0205-CFR
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
    "Policy Code": "PR-AWS-0205-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CodeDeploy application compute platform must be ECS or Lambda",
    "Policy Description": "AWS CodeDeploy application compute platform must be ECS or Lambda",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform"
}
