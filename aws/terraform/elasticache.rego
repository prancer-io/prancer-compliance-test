package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html

#
# PR-AWS-0055-TRF
#

default cache_failover = null

aws_issue["cache_failover"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    lower(resource.properties.automatic_failover_enabled) == "false"
}

aws_bool_issue["cache_failover"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    resource.properties.automatic_failover_enabled == false
}

cache_failover {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
    not aws_issue["cache_failover"]
    not aws_bool_issue["cache_failover"]
}

cache_failover = false {
    aws_issue["cache_failover"]
}

cache_failover = false {
    aws_bool_issue["cache_failover"]
}

cache_failover_err = "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled" {
    aws_issue["cache_failover"]
} else = "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled" {
    aws_bool_issue["cache_failover"]
}

cache_failover_metadata := {
    "Policy Code": "PR-AWS-0055-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Multi-AZ Automatic Failover feature set to disabled. It is recommended to enable the Multi-AZ Automatic Failover feature for your Redis Cache cluster, which will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primary's availability zone for read/write operations._x005F_x000D_ Note: Redis cluster Multi-AZ with automatic failover does not support T1 and T2 cache node types and is only available if the cluster has at least one read replica.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-0056-TRF
#

default cache_redis_auth = null

aws_attribute_absence["cache_redis_auth"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.auth_token
}

aws_issue["cache_redis_auth"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    count(resource.properties.auth_token) == 0
}

aws_issue["cache_redis_auth"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    lower(resource.properties.transit_encryption_enabled) == "false"
}

aws_bool_issue["cache_redis_auth"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.transit_encryption_enabled
}

cache_redis_auth {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
    not aws_issue["cache_redis_auth"]
    not aws_bool_issue["cache_redis_auth"]
    not aws_attribute_absence["cache_redis_auth"]
}

cache_redis_auth = false {
    aws_issue["cache_redis_auth"]
}

cache_redis_auth = false {
    aws_bool_issue["cache_redis_auth"]
}

cache_redis_auth = false {
    aws_attribute_absence["cache_redis_auth"]
}

cache_redis_auth_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_issue["cache_redis_auth"]
} else = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_bool_issue["cache_redis_auth"]
}

cache_redis_auth_miss_err = "ElastiCache Redis cluster attribute auth_token missing in the resource" {
    aws_attribute_absence["cache_redis_auth"]
}

cache_redis_auth_metadata := {
    "Policy Code": "PR-AWS-0056-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ElastiCache Redis cluster with Redis AUTH feature disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Redis AUTH feature disabled. Redis AUTH can improve data security by requiring the user to enter a password before they are granted permission to execute Redis commands on a password protected Redis server.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-0057-TRF
#

default cache_redis_encrypt = null

aws_issue["cache_redis_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    lower(resource.properties.at_rest_encryption_enabled) == "false"
}

aws_bool_issue["cache_redis_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.at_rest_encryption_enabled
}

cache_redis_encrypt {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
    not aws_issue["cache_redis_encrypt"]
    not aws_bool_issue["cache_redis_encrypt"]
}

cache_redis_encrypt = false {
    aws_issue["cache_redis_encrypt"]
}

cache_redis_encrypt = false {
    aws_bool_issue["cache_redis_encrypt"]
}

cache_redis_encrypt_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_issue["cache_redis_encrypt"]
} else = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_bool_issue["cache_redis_encrypt"]
}

cache_redis_encrypt_metadata := {
    "Policy Code": "PR-AWS-0057-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ElastiCache Redis cluster with encryption for data at rest disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have encryption for data at rest(at-rest) is disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to persistent media available on your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}


#
# PR-AWS-0058-TRF
#

default cache_encrypt = null

aws_issue["cache_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    lower(resource.properties.transit_encryption_enabled) == "false"
}

aws_bool_issue["cache_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.transit_encryption_enabled
}

cache_encrypt {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
    not aws_issue["cache_encrypt"]
    not aws_bool_issue["cache_encrypt"]
}

cache_encrypt = false {
    aws_issue["cache_encrypt"]
}

cache_encrypt = false {
    aws_bool_issue["cache_encrypt"]
}


cache_encrypt_err = "AWS ElastiCache Redis cluster with in-transit encryption disabled" {
    aws_issue["cache_encrypt"]
} else = "AWS ElastiCache Redis cluster with in-transit encryption disabled" {
    aws_bool_issue["cache_encrypt"]
}

cache_encrypt_metadata := {
    "Policy Code": "PR-AWS-0058-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ElastiCache Redis cluster with in-transit encryption disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}


#
# PR-AWS-0214-TRF
#

default cache_ksm_key = null

aws_issue["cache_ksm_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.kms_key_id
}

aws_issue["cache_ksm_key"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not startswith(resource.properties.kms_key_id, "arn:")
}

cache_ksm_key {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
    not aws_issue["cache_ksm_key"]
}

cache_ksm_key = false {
    aws_issue["cache_ksm_key"]
}

cache_ksm_key_err = "Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key" {
    aws_issue["cache_ksm_key"]
}

cache_ksm_key_metadata := {
    "Policy Code": "PR-AWS-0214-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-kmskeyid"
}


#
# PR-AWS-0215-TRF
#

default cache_default_sg = null

aws_issue["cache_default_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    not resource.properties.security_group_names
}

aws_issue["cache_default_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    count(resource.properties.security_group_names) == 0
}

aws_issue["cache_default_sg"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticache_replication_group"
    cache_sg := resource.properties.security_group_names[_]
    count([c | lower(cache_sg) == "default"; c:=1]) != 0
}

cache_default_sg {
    lower(input.resources[i].type) == "aws_elasticache_replication_group"
    not aws_issue["cache_default_sg"]
}

cache_default_sg = false {
    aws_issue["cache_default_sg"]
}

cache_default_sg_err = "Ensure 'default' value is not used on Security Group setting for Redis cache engines" {
    aws_issue["cache_default_sg"]
}

cache_default_sg_metadata := {
    "Policy Code": "PR-AWS-0215-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure 'default' value is not used on Security Group setting for Redis cache engines",
    "Policy Description": "Ensure 'default' value is not used on Security Group setting for Redis cache engines",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html#cfn-elasticache-replicationgroup-cachesubnetgroupname"
}
