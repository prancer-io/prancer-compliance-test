package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssm-parameter.html

#
# PR-AWS-0158-CFR
#

default ssm_secure = null

aws_attribute_absence["ssm_secure"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ssm::parameter"
    not resource.Properties.Type
}

aws_issue["ssm_secure"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ssm::parameter"
    lower(resource.Properties.Type) != "securestring"
}

ssm_secure {
    lower(input.Resources[i].Type) == "aws::ssm::parameter"
    not aws_issue["ssm_secure"]
    not aws_attribute_absence["ssm_secure"]
}

ssm_secure = false {
    aws_issue["ssm_secure"]
}

ssm_secure = false {
    aws_attribute_absence["ssm_secure"]
}

ssm_secure_err = "AWS SSM Parameter is not encrypted" {
    aws_issue["ssm_secure"]
}

ssm_secure_err = "SSM attribute Type missing in the resource" {
    aws_attribute_absence["ssm_secure"]
}

ssm_secure_metadata := {
    "Policy Code": "PR-AWS-0158-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS SSM Parameter is not encrypted",
    "Policy Description": "This policy identifies the AWS SSM Parameters which are not encrypted. AWS Systems Manager (SSM) parameters that store sensitive data, for example, passwords, database strings, and permit codes are encrypted so as to meet security and compliance prerequisites. An encrypted SSM parameter is any sensitive information that should be kept and referenced in a protected way.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssm-parameter.html"
}
