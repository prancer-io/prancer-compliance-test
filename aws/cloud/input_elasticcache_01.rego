#
# PR-AWS-0055
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_DescribeGlobalReplicationGroups.html

rulepass = true{
    lower(resource.Type) == "aws::elasticache::replicationgroup"
  input.ReplicationGroups[_].AutomaticFailover="enabled"
}
