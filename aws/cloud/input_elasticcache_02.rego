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

rulepass_metadata := {
    "Policy Code": "PR-AWS-0056",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS ElastiCache Redis cluster with Redis AUTH feature disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Redis AUTH feature disabled. Redis AUTH can improve data security by requiring the user to enter a password before they are granted permission to execute Redis commands on a password protected Redis server.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_DescribeGlobalReplicationGroups.html"
}
