#
# PR-AWS-0158
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeParameters.html

rulepass = true {
    # lower(input.Type) == "aws::ssm::parameter"
    input.Parameters[_].Type='SecureString'
}

metadata := {
    "Policy Code": "PR-AWS-0158",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS SSM Parameter is not encrypted",
    "Policy Description": "This policy identifies the AWS SSM Parameters which are not encrypted. AWS Systems Manager (SSM) parameters that store sensitive data, for example, passwords, database strings, and permit codes are encrypted so as to meet security and compliance prerequisites. An encrypted SSM parameter is any sensitive information that should be kept and referenced in a protected way.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeParameters.html"
}
