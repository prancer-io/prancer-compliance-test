package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html

#
# PR-AWS-0055-CFR
#

default cache_failover = null

aws_issue["cache_failover"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.AutomaticFailoverEnabled
}

cache_failover {
    lower(input.resources[_].Type) == "aws::elasticache::replicationgroup"
    not aws_issue["cache_failover"]
    not aws_attribute_absence["cache_failover"]
}

cache_failover = false {
    aws_issue["cache_failover"]
}

cache_failover_err = "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled" {
    aws_issue["cache_failover"]
}

#
# PR-AWS-0056-CFR
#

default cache_redis_auth = null

aws_attribute_absence["cache_redis_auth"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.AuthToken
}

aws_issue["cache_redis_auth"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    count(resource.Properties.AuthToken) == 0
}

aws_issue["cache_redis_auth"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.TransitEncryptionEnabled
}

cache_redis_auth {
    lower(input.resources[_].Type) == "aws::elasticache::replicationgroup"
    not aws_issue["cache_redis_auth"]
    not aws_attribute_absence["cache_redis_auth"]
}

cache_redis_auth = false {
    aws_issue["cache_redis_auth"]
}

cache_redis_auth = false {
    aws_attribute_absence["cache_redis_auth"]
}

cache_redis_auth_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_issue["cache_redis_auth"]
}

cache_redis_auth_miss_err = "ElastiCache Redis cluster attribute AuthToken missing in the resource" {
    aws_attribute_absence["cache_redis_auth"]
}

#
# PR-AWS-0057-CFR
#

default cache_redis_encrypt = null

aws_issue["cache_redis_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.AtRestEncryptionEnabled
}

cache_redis_encrypt {
    lower(input.resources[_].Type) == "aws::elasticache::replicationgroup"
    not aws_issue["cache_redis_encrypt"]
}

cache_redis_encrypt = false {
    aws_issue["cache_redis_encrypt"]
}

cache_redis_encrypt_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_issue["cache_redis_encrypt"]
}

#
# PR-AWS-0058-CFR
#

default cache_encrypt = null

aws_issue["cache_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticache::replicationgroup"
    not resource.Properties.AtRestEncryptionEnabled
}

cache_encrypt {
    lower(input.resources[_].Type) == "aws::elasticache::replicationgroup"
    not aws_issue["cache_encrypt"]
}

cache_encrypt = false {
    aws_issue["cache_encrypt"]
}

cache_encrypt_err = "AWS ElastiCache Redis cluster with in-transit encryption disabled" {
    aws_issue["cache_encrypt"]
}
