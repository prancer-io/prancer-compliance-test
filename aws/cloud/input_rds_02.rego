#
# PR-AWS-0125
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass {
   db_instance := input.DBInstances[_]
   db_instance.StorageEncrypted == true
}

# If storage encryption is set to enabled then test will pass.
