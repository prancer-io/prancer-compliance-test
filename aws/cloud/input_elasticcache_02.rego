#
# PR-AWS-0056
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_DescribeGlobalReplicationGroups.html

rulepass = true {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    input.ReplicationGroups[_].AuthTokenEnabled=true
    input.ReplicationGroups[_].TransitEncryptionEnabled=true
}
