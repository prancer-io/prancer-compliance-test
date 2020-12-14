#
# PR-AWS-0056
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_DescribeGlobalReplicationGroups.html

rulepass = true{
  input.ReplicationGroups[_].AuthTokenEnabled=true
  input.ReplicationGroups[_].TransitEncryptionEnabled=true
}
