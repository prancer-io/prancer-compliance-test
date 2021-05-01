package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html

#
# PR-AWS-0105-TRF
#

default lambda_env = null

aws_attribute_absence["lambda_env"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.kms_key_arn
}

aws_attribute_absence["lambda_env"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.environment
}

aws_issue["lambda_env"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_lambda_function"
    resource.properties.environment
    not resource.properties.kms_key_arn
}

aws_issue["lambda_env"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_lambda_function"
    resource.properties.environment
    not startswith(lower(resource.properties.kms_key_arn), "arn:")
}

lambda_env {
    lower(input.resources[_].type) == "aws_lambda_function"
    not aws_issue["lambda_env"]
    not aws_attribute_absence["lambda_env"]
}

lambda_env = false {
    aws_issue["lambda_env"]
}

lambda_env = false {
    aws_attribute_absence["lambda_env"]
}

lambda_env_err = "AWS Lambda environment Variables not encrypted at-rest using CMK" {
    aws_issue["lambda_env"]
}

lambda_env_miss_err = "Lambda function attribute kms_key_arn/environment missing in the resource" {
    aws_attribute_absence["lambda_env"]
}

#
# PR-AWS-0106-TRF
#

default lambda_vpc = null

aws_attribute_absence["lambda_vpc"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.vpc_config.subnet_ids
}

aws_issue["lambda_vpc"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_lambda_function"
    count(resource.properties.vpc_config.subnet_ids) == 0
}

lambda_vpc {
    lower(input.resources[_].type) == "aws_lambda_function"
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

lambda_vpc_miss_err = "Lambda function attribute vpc_config.subnet_ids missing in the resource" {
    aws_attribute_absence["lambda_vpc"]
}

#
# PR-AWS-0107-TRF
#

default lambda_tracing = null

aws_attribute_absence["lambda_tracing"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.tracing_config.mode
}

aws_issue["lambda_tracing"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_lambda_function"
    lower(resource.properties.tracing_config.mode) == "passthrough"
}

lambda_tracing {
    lower(input.resources[_].type) == "aws_lambda_function"
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

lambda_tracing_miss_err = "Lambda function attribute tracing_config.mode missing in the resource" {
    aws_attribute_absence["lambda_tracing"]
}
