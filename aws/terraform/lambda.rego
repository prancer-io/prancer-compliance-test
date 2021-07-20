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
    resource.properties.kms_key_arn != null
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

lambda_env_metadata := {
    "Policy Code": "PR-AWS-0105-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Lambda Environment Variables not encrypted at-rest using CMK",
    "Policy Description": "When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.",
    "Resource Type": "aws_lambda_function",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
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

lambda_vpc_metadata := {
    "Policy Code": "PR-AWS-0106-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Lambda Function is not assigned to access within VPC",
    "Policy Description": "This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).",
    "Resource Type": "aws_lambda_function",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
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

lambda_tracing_metadata := {
    "Policy Code": "PR-AWS-0107-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Lambda functions with tracing not enabled",
    "Policy Description": "TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.",
    "Resource Type": "aws_lambda_function",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}
