package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html

#
# PR-AWS-0105-CFR
#

default lambda_env = null

aws_attribute_absence["lambda_env"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.KmsKeyArn
}

aws_attribute_absence["lambda_env"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.Environment
}

aws_issue["lambda_env"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::lambda::function"
    resource.Properties.Environment
    not resource.Properties.KmsKeyArn
}

aws_issue["lambda_env"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::lambda::function"
    resource.Properties.Environment
    not startswith(lower(resource.Properties.KmsKeyArn), "arn:")
}

lambda_env {
    lower(input.resources[_].Type) == "aws::lambda::function"
    not aws_issue["lambda_env"]
    not aws_attribute_absence["lambda_env"]
}

lambda_env = false {
    aws_issue["lambda_env"]
}

lambda_env = false {
    aws_attribute_absence["lambda_env"]
}

lambda_env_err = "AWS Lambda Environment Variables not encrypted at-rest using CMK" {
    aws_issue["lambda_env"]
}

lambda_env_miss_err = "Lambda function attribute KmsKeyArn/Environment missing in the resource" {
    aws_attribute_absence["lambda_env"]
}

#
# PR-AWS-0106-CFR
#

default lambda_vpc = null

aws_attribute_absence["lambda_vpc"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.VpcConfig.SubnetIds
}

aws_issue["lambda_vpc"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::lambda::function"
    count(resource.Properties.VpcConfig.SubnetIds) == 0
}

lambda_vpc {
    lower(input.resources[_].Type) == "aws::lambda::function"
    not aws_issue["lambda_vpc"]
    not aws_attribute_absence["lambda_vpc"]
}

lambda_vpc = false {
    aws_issue["lambda_vpc"]
}

lambda_vpc = false {
    aws_attribute_absence["lambda_vpc"]
}

lambda_vpc_err = "AWS Lambda Function is not assigned to access within VPC" {
    aws_issue["lambda_vpc"]
}

lambda_vpc_miss_err = "Lambda function attribute VpcConfig.SubnetIds missing in the resource" {
    aws_attribute_absence["lambda_vpc"]
}

#
# PR-AWS-0107-CFR
#

default lambda_tracing = null

aws_attribute_absence["lambda_tracing"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.TracingConfig.Mode
}

aws_issue["lambda_tracing"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::lambda::function"
    lower(resource.Properties.TracingConfig.Mode) == "passthrough"
}

lambda_tracing {
    lower(input.resources[_].Type) == "aws::lambda::function"
    not aws_issue["lambda_tracing"]
    not aws_attribute_absence["lambda_tracing"]
}

lambda_tracing = false {
    aws_issue["lambda_tracing"]
}

lambda_tracing = false {
    aws_attribute_absence["lambda_tracing"]
}

lambda_tracing_err = "AWS Lambda functions with tracing not enabled" {
    aws_issue["lambda_tracing"]
}

lambda_tracing_miss_err = "Lambda function attribute TracingConfig.Mode missing in the resource" {
    aws_attribute_absence["lambda_tracing"]
}
