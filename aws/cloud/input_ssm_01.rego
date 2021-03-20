#
# PR-AWS-0158
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeParameters.html

rulepass = true {
    lower(resource.Type) == "aws::ssm::parameter"
    input.Parameters[_].Type='SecureString'
}
