package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html

#
# PR-AWS-CFR-LMD-001
# aws::lambda::function
#

default lambda_env = true

lambda_env = false {
    input.Configuration.Environment
    not input.Configuration.KMSKeyArn
}

lambda_env = false {
    input.Configuration.Environment
    not startswith(lower(input.Configuration.KMSKeyArn), "arn:")
}

lambda_env_err = "AWS Lambda Environment Variables not encrypted at-rest using CMK" {
    not lambda_env
}

lambda_env_metadata := {
    "Policy Code": "PR-AWS-CFR-LMD-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Lambda Environment Variables not encrypted at-rest using CMK",
    "Policy Description": "When you create or update Lambda functions that use Environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code.<br><br>This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}

#
# PR-AWS-CFR-LMD-002
# aws::lambda::function
#

default lambda_vpc = true

lambda_vpc = false {
    not input.Configuration.VpcConfig.SubnetIds
}

lambda_vpc = false {
    count(input.Configuration.VpcConfig.SubnetIds) == 0
}

lambda_vpc_err = "AWS Lambda Function is not assigned to access within VPC" {
    not lambda_vpc
}

lambda_vpc_metadata := {
    "Policy Code": "PR-AWS-CFR-LMD-002",
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
# PR-AWS-CFR-LMD-003
# aws::lambda::function
#

default lambda_tracing = true

lambda_tracing = false {
    not input.Configuration.TracingConfig.Mode
}

lambda_tracing = false {
    lower(input.Configuration.TracingConfig.Mode) == "passthrough"
}

lambda_tracing_err = "AWS Lambda functions with tracing not enabled" {
    not lambda_tracing
}

lambda_tracing_metadata := {
    "Policy Code": "PR-AWS-CFR-LMD-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Lambda functions with tracing not enabled",
    "Policy Description": "TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors.<br><br>The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}


#
# PR-AWS-CFR-LMD-004
# aws::lambda::function
#

default lambda_concurrent_execution = true

lambda_concurrent_execution = false {
    not input.Concurrency.ReservedConcurrentExecutions
}

lambda_concurrent_execution_err = "Ensure AWS Lambda function is configured for function-level concurrent execution limit" {
    not lambda_concurrent_execution
}

lambda_concurrent_execution_metadata := {
    "Policy Code": "PR-AWS-CFR-LMD-004",
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
# PR-AWS-CFR-LMD-005
# aws::lambda::function
#

default lambda_dlq = true

lambda_dlq = false {
    not input.Configuration.DeadLetterConfig.TargetArn
}

lambda_dlq_err = "Ensure AWS Lambda function is configured for a DLQ" {
    not lambda_dlq
}

lambda_dlq_metadata := {
    "Policy Code": "PR-AWS-CFR-LMD-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS Lambda function is configured for a DLQ",
    "Policy Description": "A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-deadletterconfig"
}


#
# PR-AWS-CFR-LMD-009
# aws::lambda::function
#

default lambda_encryption = true

lambda_encryption = false {
    not input.Configuration.KMSKeyArn
}

lambda_encryption_err = "AWS Lambda not encrypted at-rest using CMK" {
    not lambda_encryption
}

lambda_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-LMD-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Lambda not encrypted at-rest using CMK",
    "Policy Description": "When you create or update Lambda functions that use Environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code.<br><br>This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}
