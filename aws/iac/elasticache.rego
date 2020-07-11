package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html

#
# Id: 55
#

default cache_failover = null

cache_failover {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    input.Properties.AutomaticFailoverEnabled == true
}

cache_failover = false {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    input.Properties.AutomaticFailoverEnabled == false
}

cache_failover = false {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    not input.Properties.AutomaticFailoverEnabled
}

cache_failover_err = "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled" {
    cache_failover == false
}

#
# Id: 56
#

default cache_redis_auth = null

cache_redis_auth {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    input.Properties.TransitEncryptionEnabled == true
    count(input.Properties.AuthToken) > 0
}

cache_redis_auth = false {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    count(input.Properties.AuthToken) == 0
}

cache_redis_auth = false {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    input.Properties.TransitEncryptionEnabled == false
}

cache_redis_auth = false {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    not input.Properties.AuthToken
}

cache_redis_auth = false {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    not input.Properties.TransitEncryptionEnabled
}

cache_redis_auth_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    cache_redis_auth == false
}

#
# Id: 57
#

default cache_redis_encrypt = null

cache_redis_encrypt {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    input.Properties.AtRestEncryptionEnabled == true
}

cache_redis_encrypt = false {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    input.Properties.AtRestEncryptionEnabled == false
}

cache_redis_encrypt = false {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    not input.Properties.AtRestEncryptionEnabled
}

cache_redis_encrypt_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    cache_redis_encrypt == false
}

#
# Id: 58
#

default cache_encrypt = null

cache_encrypt {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    input.Properties.TransitEncryptionEnabled == true
}

cache_encrypt = false {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    input.Properties.TransitEncryptionEnabled == false
}

cache_encrypt = false {
    lower(input.Type) == "aws::elasticache::replicationgroup"
    not input.Properties.TransitEncryptionEnabled
}

cache_encrypt_err = "AWS ElastiCache Redis cluster with in-transit encryption disabled" {
    cache_encrypt == false
}
