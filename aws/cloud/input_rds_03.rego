#
# PR-AWS-0128
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass {
    lower(input.Type) == "aws::rds::dbinstance"
    db_instance := input.DBInstances[_]
    db_instance.CopyTagsToSnapshot == true
}

# If CopyTagsToSnapshot is enabled then test will pass.
