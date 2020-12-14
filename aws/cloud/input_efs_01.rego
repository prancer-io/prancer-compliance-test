#
# PR-AWS-0061
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html

rulepass = false {
    input.FileSystems[_].Encrypted == false
}
