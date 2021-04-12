#
# PR-AWS-0061
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html

rulepass = false {
    lower(input.Type) == "aws::efs::filesystem"
    input.FileSystems[_].Encrypted == false
}
