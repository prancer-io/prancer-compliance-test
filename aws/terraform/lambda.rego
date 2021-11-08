package rule


#
# PR-AWS-TRF-LMD-001
#

default lambda_env = null

aws_attribute_absence["lambda_env"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.kms_key_arn
}

source_path[{"lambda_env": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.kms_key_arn

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_arn"]
        ],
    }
}

aws_attribute_absence["lambda_env"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.environment
}

source_path[{"lambda_env": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.environment

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "environment"]
        ],
    }
}

aws_issue["lambda_env"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    is_null(resource.properties.kms_key_arn)
}

source_path[{"lambda_env": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    is_null(resource.properties.kms_key_arn)

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_arn"]
        ],
    }
}

aws_issue["lambda_env"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    resource.properties.environment
    not resource.properties.kms_key_arn
}

source_path[{"lambda_env": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    resource.properties.environment
    not resource.properties.kms_key_arn

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_arn"]
        ],
    }
}

aws_issue["lambda_env"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    resource.properties.environment
    not startswith(lower(resource.properties.kms_key_arn), "arn:")
}

source_path[{"lambda_env": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    resource.properties.environment
    not startswith(lower(resource.properties.kms_key_arn), "arn:")

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "kms_key_arn"]
        ],
    }
}

lambda_env {
    lower(input.resources[i].type) == "aws_lambda_function"
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
} else = "Lambda function attribute kms_key_arn/environment missing in the resource" {
    aws_attribute_absence["lambda_env"]
}

lambda_env_metadata := {
    "Policy Code": "PR-AWS-TRF-LMD-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Lambda Environment Variables not encrypted at-rest using CMK",
    "Policy Description": "When you create or update Lambda functions that use environment variables, AWS Lambda encrypts them using the AWS Key Management Service. When your Lambda function is invoked, those values are decrypted and made available to the Lambda code.<br><br>This policy verifies that Lambda function uses the AMS Key Management Service to encrypt variables at-rest with CMK.",
    "Resource Type": "aws_lambda_function",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}

#
# PR-AWS-TRF-LMD-002
#

default lambda_vpc = null

aws_attribute_absence["lambda_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.vpc_config
}

source_path[{"lambda_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.vpc_config

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "vpc_config"]
        ],
    }
}

aws_attribute_absence["lambda_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    count(resource.properties.vpc_config) == 0
}

source_path[{"lambda_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    count(resource.properties.vpc_config) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "vpc_config"]
        ],
    }
}

aws_issue["lambda_vpc"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    vpc_config := resource.properties.vpc_config[j]
    count(vpc_config.subnet_ids) == 0
}

source_path[{"lambda_vpc": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    vpc_config := resource.properties.vpc_config[j]
    count(vpc_config.subnet_ids) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "vpc_config", j, "subnet_ids"]
        ],
    }
}

lambda_vpc {
    lower(input.resources[i].type) == "aws_lambda_function"
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
} else = "Lambda function attribute vpc_config.subnet_ids missing in the resource" {
    aws_attribute_absence["lambda_vpc"]
}

lambda_vpc_metadata := {
    "Policy Code": "PR-AWS-TRF-LMD-002",
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
# PR-AWS-TRF-LMD-003
#

default lambda_tracing = null

aws_attribute_absence["lambda_tracing"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.tracing_config
}

source_path[{"lambda_tracing": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.tracing_config

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "tracing_config"]
        ],
    }
}

aws_attribute_absence["lambda_tracing"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    count(resource.properties.tracing_config) == 0
}

source_path[{"lambda_tracing": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    count(resource.properties.tracing_config) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "tracing_config"]
        ],
    }
}

aws_attribute_absence["lambda_tracing"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    tracing_config := resource.properties.tracing_config[j]
    not tracing_config.mode
}

source_path[{"lambda_tracing": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    count(resource.properties.tracing_config) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "tracing_config"]
        ],
    }
}

aws_issue["lambda_tracing"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    tracing_config := resource.properties.tracing_config[j]
    lower(tracing_config.mode) == "passthrough"
}

source_path[{"lambda_tracing": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    tracing_config := resource.properties.tracing_config[j]
    lower(tracing_config.mode) == "passthrough"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "tracing_config", j, "mode"]
        ],
    }
}

lambda_tracing {
    lower(input.resources[i].type) == "aws_lambda_function"
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
} else = "Lambda function attribute tracing_config.mode missing in the resource" {
    aws_attribute_absence["lambda_tracing"]
}

lambda_tracing_metadata := {
    "Policy Code": "PR-AWS-TRF-LMD-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Lambda functions with tracing not enabled",
    "Policy Description": "TracingConfig is a property of the AWS::Lambda::Function resource that configures tracing settings for your AWS Lambda (Lambda) function. When enabled, AWS Lambda tracing acitivates AWS X-Ray service that collects information on requests that a specific function performed. It reduces the time and effort for debugging and diagnosing the errors.<br><br>The value can be either PassThrough or Active. If PassThrough, Lambda will only trace the request from an upstream service if it contains a tracing header with 'sampled=1'. If Active, Lambda will respect any tracing header it receives from an upstream service. If no tracing header is received, Lambda will call X-Ray for a tracing decision.",
    "Resource Type": "aws_lambda_function",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"
}


#
# PR-AWS-TRF-LMD-004
#

default lambda_concurrent_execution = null

aws_issue["lambda_concurrent_execution"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.reserved_concurrent_executions
}

source_path[{"lambda_concurrent_execution": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    not resource.properties.reserved_concurrent_executions
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "reserved_concurrent_executions"]
        ],
    }
}

lambda_concurrent_execution {
    lower(input.resources[i].type) == "aws_lambda_function"
    not aws_issue["lambda_concurrent_execution"]
}

lambda_concurrent_execution = false {
    aws_issue["lambda_concurrent_execution"]
}

lambda_concurrent_execution_err = "Ensure AWS Lambda function is configured for function-level concurrent execution limit" {
    aws_issue["lambda_concurrent_execution"]
}

lambda_concurrent_execution_metadata := {
    "Policy Code": "PR-AWS-TRF-LMD-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS Lambda function is configured for function-level concurrent execution limit",
    "Policy Description": "Concurrency is the number of requests that your function is serving at any given time. When your function is invoked, Lambda allocates an instance of it to process the event",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#target_arn"
}



#
# PR-AWS-TRF-LMD-005
#

default lambda_dlq = null

aws_issue["lambda_dlq"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    dead_letter_config := resource.properties.dead_letter_config[_]
    not dead_letter_config.target_arn
}

source_path[{"lambda_dlq": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lambda_function"
    dead_letter_config := resource.properties.dead_letter_config[_]
    not dead_letter_config.target_arn
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "dead_letter_config", "target_arn"]
        ],
    }
}

lambda_dlq {
    lower(input.resources[i].type) == "aws_lambda_function"
    not aws_issue["lambda_dlq"]
}

lambda_dlq = false {
    aws_issue["lambda_dlq"]
}

lambda_dlq_err = "Ensure AWS Lambda function is configured for a DLQ" {
    aws_issue["lambda_dlq"]
}

lambda_dlq_metadata := {
    "Policy Code": "PR-AWS-TRF-LMD-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS Lambda function is configured for a DLQ",
    "Policy Description": "A dead letter queue configuration that specifies the queue or topic where Lambda sends asynchronous events when they fail processing. it is required to get all items which is been not processed for some reason",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#target_arn"
}
