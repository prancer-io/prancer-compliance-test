package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssm-parameter.html

#
# PR-AWS-0158-CFR
#

default ssm_secure = null

aws_attribute_absence["ssm_secure"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ssm::parameter"
    not resource.Properties.Type
}

aws_issue["ssm_secure"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::ssm::parameter"
    lower(resource.Properties.Type) != "securestring"
}

ssm_secure {
    lower(input.resources[_].Type) == "aws::ssm::parameter"
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

ssm_secure_miss_err = "SSM attribute Type missing in the resource" {
    aws_attribute_absence["ssm_secure"]
}
