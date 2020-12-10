#
# PR-AWS-0131
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass = false {
   db_instance := input.DBInstances[_]
   to_number(db_instance.BackupRetentionPeriod) < 7
}
