package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}


# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html

#
# PR-AWS-CFR-LMD-001
#

default lambda_env = null

aws_attribute_absence["lambda_env"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.KmsKeyArn
}

source_path[{"lambda_env": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.KmsKeyArn
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KmsKeyArn"]
        ],
    }
}

aws_attribute_absence["lambda_env"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.Environment
}

source_path[{"lambda_env": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.Environment
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Environment"]
        ],
    }
}

aws_issue["lambda_env"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    resource.Properties.Environment
    not resource.Properties.KmsKeyArn
}

source_path[{"lambda_env": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    resource.Properties.Environment
    not resource.Properties.KmsKeyArn
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KmsKeyArn"]
        ],
    }
}

aws_issue["lambda_env"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    resource.Properties.Environment
    not startswith(lower(resource.Properties.KmsKeyArn), "arn:")
}

source_path[{"lambda_env": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    resource.Properties.Environment
    not startswith(lower(resource.Properties.KmsKeyArn), "arn:")
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "KmsKeyArn"]
        ],
    }
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
    "Policy Code": "PR-AWS-CFR-LMD-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Lambda Environment Variables not encrypted at-rest using CMK",
    "Policy Description": "When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code.<br><br>This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}

#
# PR-AWS-CFR-LMD-002
#

default lambda_vpc = null

aws_attribute_absence["lambda_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.VpcConfig.SubnetIds
}

source_path[{"lambda_vpc": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.VpcConfig.SubnetIds
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "VpcConfig", "SubnetIds"]
        ],
    }
}

aws_issue["lambda_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    count(resource.Properties.VpcConfig.SubnetIds) == 0
}

source_path[{"lambda_vpc": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    count(resource.Properties.VpcConfig.SubnetIds) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "VpcConfig", "SubnetIds"]
        ],
    }
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
#

default lambda_tracing = null

aws_attribute_absence["lambda_tracing"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.TracingConfig.Mode
}

source_path[{"lambda_tracing": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.TracingConfig.Mode
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "TracingConfig", "Mode"]
        ],
    }
}

aws_issue["lambda_tracing"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    lower(resource.Properties.TracingConfig.Mode) == "passthrough"
}

source_path[{"lambda_tracing": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    lower(resource.Properties.TracingConfig.Mode) == "passthrough"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "TracingConfig", "Mode"]
        ],
    }
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
#

default lambda_concurrent_execution = null

aws_issue["lambda_concurrent_execution"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.ReservedConcurrentExecutions
}

source_path[{"lambda_concurrent_execution": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.ReservedConcurrentExecutions
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ReservedConcurrentExecutions"]
        ],
    }
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
#

default lambda_dlq = null

aws_issue["lambda_dlq"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.DeadLetterConfig.TargetArn
}

source_path[{"lambda_dlq": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    not resource.Properties.DeadLetterConfig.TargetArn
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DeadLetterConfig", "TargetArn"]
        ],
    }
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
# PR-AWS-CFR-LMD-006
#

default lambda_eventsourcemapping_unsupported_properties = null

not_allowed_properties = [
	"SourceAccessConfigurations",
	"SelfManagedEventSource",
	"Topics",
	"Queues",
]

aws_issue["lambda_eventsourcemapping_unsupported_properties"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::eventsourcemapping"
    has_property(resource, not_allowed_properties[_])
}

lambda_eventsourcemapping_unsupported_properties {
    lower(input.Resources[i].Type) == "aws::lambda::eventsourcemapping"
    not aws_issue["lambda_eventsourcemapping_unsupported_properties"]
}

lambda_eventsourcemapping_unsupported_properties = false {
    aws_issue["lambda_eventsourcemapping_unsupported_properties"]
}

lambda_eventsourcemapping_unsupported_properties_err = "Ensure unsupported properties on Lambda EventSourceMapping are not set." {
    aws_issue["lambda_eventsourcemapping_unsupported_properties"]
}

lambda_eventsourcemapping_unsupported_properties_metadata := {
    "Policy Code": "PR-AWS-CFR-LMD-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure unsupported properties on Lambda EventSourceMapping are not set.",
    "Policy Description": "Ensure that unsupported properties on AWS::Lambda::EventSourceMapping are not set",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-deadletterconfig"
}


#
# PR-AWS-CFR-LMD-007
#

default lambda_require_zip_package = null

aws_issue["lambda_require_zip_package"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    lower(resource.Properties.PackageType) != "zip"
}

lambda_require_zip_package {
    lower(input.Resources[i].Type) == "aws::lambda::function"
    not aws_issue["lambda_require_zip_package"]
}

lambda_require_zip_package = false {
    aws_issue["lambda_require_zip_package"]
}

lambda_require_zip_package_err = "Lambda Function PackageType value is limited to Zip" {
    aws_issue["lambda_require_zip_package"]
}

lambda_require_zip_package_metadata := {
    "Policy Code": "PR-AWS-CFR-LMD-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Lambda Function PackageType value is limited to Zip",
    "Policy Description": "Ensure that the AWS::Lambda::Function PackageType value is limited to Zip.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-deadletterconfig"
}


#
# PR-AWS-CFR-LMD-008
#

default lambda_runtime = null

ALLOWED_RUNTIMES = {"java11", "python3.6", "python3.7", "python3.8", "python3.9", "nodejs12.", "nodejs14.", "go1."}

aws_issue["lambda_runtime"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::lambda::function"
    count([c | contains(lower(resource.Properties.Runtime), ALLOWED_RUNTIMES[_]); c:=1 ]) == 0
}

lambda_runtime {
    lower(input.Resources[i].Type) == "aws::lambda::function"
    not aws_issue["lambda_runtime"]
}

lambda_runtime = false {
    aws_issue["lambda_runtime"]
}

lambda_runtime_err = "Limit lambda runtimes to allowed list" {
    aws_issue["lambda_runtime"]
}

lambda_runtime_metadata := {
    "Policy Code": "PR-AWS-CFR-LMD-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Limit lambda runtimes to allowed list",
    "Policy Description": "Ensure that AWS::Lambda::Function Runtime values are limited to a vetted list of allowed runtimes",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-deadletterconfig"
}
