#
# PR-AWS-0106
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html

rulepass {
    lower(input.Type) == "aws::lambda::function"
    input.Configuration.VpcConfig
    input.Configuration.VpcConfig.VpcId
}

metadata := {
    "Policy Code": "PR-AWS-0106",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Lambda Function is not assigned to access within VPC",
    "Policy Description": "This policy identifies the AWS Lambda functions which do not have access within the VPC. Amazon Lambda functions should have access to VPC-only resources such as AWS Redshift data warehouses, AWS ElastiCache clusters, AWS RDS database instances, and service endpoints that should be only accessible from within a particular Virtual Private Cloud (VPC).",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/lambda/latest/dg/API_GetFunction.html"
}

#If the VPC network is configured with LAMBDA then test will pass
