#
# PR-AWS-0122
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
    instance := input.DBInstances[_]
    instance.PerformanceInsightsKMSKeyId
}
