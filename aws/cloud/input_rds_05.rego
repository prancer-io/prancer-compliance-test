#
# PR-AWS-0127
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass {
    instance := input.DBInstances[_]
    instance.MultiAZ
    instance.MultiAZ == true
}

# If multi availability zone is enabled then test will pass.
