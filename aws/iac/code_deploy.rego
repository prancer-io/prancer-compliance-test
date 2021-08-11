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

deploy_compute_platform = "Compute Platform must be 'ECS' OR 'Lambda'." {
    aws_issue["deploy_compute_platform"]
}


deploy_compute_platform_metadata := {
    "Policy Code": "PR-AWS-0205-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Compute Platform must be 'ECS' OR 'Lambda'.",
    "Policy Description": "Compute Platform must be 'ECS' OR 'Lambda'.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codedeploy-application.html#cfn-codedeploy-application-computeplatform"
}
