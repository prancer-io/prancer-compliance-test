package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html

#
# Id: 105
#

default lambda_env = null

lambda_env {
    lower(input.Type) == "aws::lambda::function"
    startswith(lower(input.Properties.KmsKeyArn), "arn:")
}

lambda_env {
    lower(input.Type) == "aws::lambda::function"
    not input.Properties.Environment
}

lambda_env = false {
    lower(input.Type) == "aws::lambda::function"
    input.Properties.Environment
    not input.Properties.KmsKeyArn
}

lambda_env = false {
    lower(input.Type) == "aws::lambda::function"
    input.Properties.Environment
    not startswith(lower(input.Properties.KmsKeyArn), "arn:")
}

lambda_env_err = "AWS Lambda Environment Variables not encrypted at-rest using CMK" {
    lambda_env == false
}

#
# Id: 106
#

default lambda_vpc = null

lambda_vpc {
    lower(input.Type) == "aws::lambda::function"
    count(input.Properties.VpcConfig.SubnetIds) > 0
}

lambda_vpc = false {
    lower(input.Type) == "aws::lambda::function"
    count(input.Properties.VpcConfig.SubnetIds) == 0
}

lambda_vpc = false {
    lower(input.Type) == "aws::lambda::function"
    not input.Properties.VpcConfig.SubnetIds
}

lambda_vpc_err = "AWS Lambda Function is not assigned to access within VPC" {
    lambda_vpc == false
}

#
# Id: 107
#

default lambda_tracing = null

lambda_tracing {
    lower(input.Type) == "aws::lambda::function"
    lower(input.Properties.TracingConfig.Mode) != "passthrough"
}

lambda_tracing = false {
    lower(input.Type) == "aws::lambda::function"
    lower(input.Properties.TracingConfig.Mode) == "passthrough"
}

lambda_tracing_err = "AWS Lambda functions with tracing not enabled" {
    lambda_tracing == false
}
