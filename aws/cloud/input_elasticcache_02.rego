package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_DescribeGlobalReplicationGroups.html
# Id : 56

rulepass = true{
  input.ReplicationGroups[_].AuthTokenEnabled=true
  input.ReplicationGroups[_].TransitEncryptionEnabled=true
}
