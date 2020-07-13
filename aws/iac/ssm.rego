package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ssm-parameter.html

#
# Id: 158
#

default ssm_secure = null

ssm_secure {
    lower(input.Type) == "aws::ssm::parameter"
    lower(input.Properties.Type) == "securestring"
}

ssm_secure = false {
    lower(input.Type) == "aws::ssm::parameter"
    lower(input.Properties.Type) != "securestring"
}

ssm_secure_err = "AWS SSM Parameter is not encrypted" {
    ssm_secure == false
}
