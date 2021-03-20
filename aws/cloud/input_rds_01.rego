#
# PR-AWS-0129
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass {
    lower(input.Resources[i].Type) == "aws::rds::dbinstance"
    db_instance := input.DBInstances[_]
    to_number(db_instance.BackupRetentionPeriod) > 0
}

# If BackupRetentionPeriod is set for database instance then test will pass.
