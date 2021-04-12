#
# PR-AWS-0130
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass = false {
    lower(input.Type) == "aws::rds::dbinstance"
    input.DBInstances[_].AutoMinorVersionUpgrade = false
}
