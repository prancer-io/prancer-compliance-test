package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html

#
# PR-AWS-0105-CFR
#

default lambda_env = null

aws_attribute_absence["lambda_env"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.KmsKeyArn
}

aws_attribute_absence["lambda_env"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.Environment
}

aws_issue["lambda_env"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    resource.Properties.Environment
    not resource.Properties.KmsKeyArn
}

aws_issue["lambda_env"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    resource.Properties.Environment
    not startswith(lower(resource.Properties.KmsKeyArn), "arn:")
}

lambda_env {
    lower(input.Resources[i].Type) == "aws::lambda::function"
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

lambda_env_metadata := {
    "Policy Code": "PR-AWS-0105-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Lambda Environment Variables not encrypted at-rest using CMK",
    "Policy Description": "When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code._x005F_x000D_ _x005F_x000D_ This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}

#
# PR-AWS-0106-CFR
#

default lambda_vpc = null

aws_attribute_absence["lambda_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.VpcConfig.SubnetIds
}

aws_issue["lambda_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    count(resource.Properties.VpcConfig.SubnetIds) == 0
}

lambda_vpc {
    lower(input.Resources[i].Type) == "aws::lambda::function"
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

lambda_vpc_metadata := {
    "Policy Code": "PR-AWS-0106-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Lambda Function is not assigned to access within VPC",
    "Policy Description": "This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}

#
# PR-AWS-0107-CFR
#

default lambda_tracing = null

aws_attribute_absence["lambda_tracing"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.TracingConfig.Mode
}

aws_issue["lambda_tracing"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    lower(resource.Properties.TracingConfig.Mode) == "passthrough"
}

lambda_tracing {
    lower(input.Resources[i].Type) == "aws::lambda::function"
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

lambda_tracing_metadata := {
    "Policy Code": "PR-AWS-0107-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Lambda functions with tracing not enabled",
    "Policy Description": "TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors._x005F_x000D_ _x005F_x000D_ The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}


#
# PR-AWS-305-CFR
#

default lambda_concurrent_execution = null

aws_issue["lambda_concurrent_execution"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.ReservedConcurrentExecutions
}

lambda_concurrent_execution {
    lower(input.Resources[i].Type) == "aws::lambda::function"
    not aws_issue["lambda_concurrent_execution"]
}

lambda_concurrent_execution = false {
    aws_issue["lambda_concurrent_execution"]
}

lambda_concurrent_execution_err = "Ensure AWS Lambda function is configured for function-level concurrent execution limit" {
    aws_issue["lambda_concurrent_execution"]
}

lambda_concurrent_execution_metadata := {
    "Policy Code": "PR-AWS-305-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS Lambda function is configured for function-level concurrent execution limit",
    "Policy Description": "Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-reservedconcurrentexecutions"
}



#
# PR-AWS-306-CFR
#

default lambda_dlq = null

aws_issue["lambda_dlq"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.DeadLetterConfig.TargetArn
}

lambda_dlq {
    lower(input.Resources[i].Type) == "aws::lambda::function"
    not aws_issue["lambda_dlq"]
}

lambda_dlq = false {
    aws_issue["lambda_dlq"]
}

lambda_dlq_err = "Ensure AWS Lambda function is configured for a DLQ" {
    aws_issue["lambda_dlq"]
}

lambda_dlq_metadata := {
    "Policy Code": "PR-AWS-306-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS Lambda function is configured for a DLQ",
    "Policy Description": "A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-deadletterconfig"
}
