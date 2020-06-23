package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_DescribeGlobalReplicationGroups.html
# Id: 55

rulepass = true{
  input.ReplicationGroups[_].AutomaticFailover="enabled"
}
