package rule

# https://github.com/aws-controllers-k8s/elasticache-controller

#
# PR-AWS-0055-ACK
#

default cache_failover = null

aws_issue["cache_failover"] {
    resource := input.Resources[i]
    lower(resource.kind) == "replicationgroup"
    not resource.spec.automaticFailoverEnabled
}

cache_failover {
    lower(input.Resources[i].kind) == "replicationgroup"
    not aws_issue["cache_failover"]
}

cache_failover = false {
    aws_issue["cache_failover"]
}

cache_failover_err = "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled" {
    aws_issue["cache_failover"]
}

cache_failover_metadata := {
    "Policy Code": "PR-AWS-0055-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Multi-AZ Automatic Failover feature set to disabled. It is recommended to enable the Multi-AZ Automatic Failover feature for your Redis Cache cluster, which will improve primary node reachability by providing read replica in case of network connectivity loss or loss of availability in the primary's availability zone for read/write operations.<br>Note: Redis cluster Multi-AZ with automatic failover does not support T1 and T2 cache node types and is only available if the cluster has at least one read replica.",
    "Resource Type": "ReplicationGroup",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-0056-ACK
#

default cache_redis_auth = null

aws_issue["cache_redis_auth"] {
    resource := input.Resources[i]
    lower(resource.kind) == "replicationgroup"
    not resource.spec.authToken
}

aws_issue["cache_redis_auth"] {
    resource := input.Resources[i]
    lower(resource.kind) == "replicationgroup"
    count(resource.spec.authToken) == 0
}

aws_issue["cache_redis_auth"] {
    resource := input.Resources[i]
    lower(resource.kind) == "replicationgroup"
    not resource.spec.transitEncryptionEnabled
}

cache_redis_auth {
    lower(input.Resources[i].kind) == "replicationgroup"
    not aws_issue["cache_redis_auth"]
}

cache_redis_auth = false {
    aws_issue["cache_redis_auth"]
}

cache_redis_auth_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_issue["cache_redis_auth"]
}

cache_redis_auth_metadata := {
    "Policy Code": "PR-AWS-0056-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS ElastiCache Redis cluster with Redis AUTH feature disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have Redis AUTH feature disabled. Redis AUTH can improve data security by requiring the user to enter a password before they are granted permission to execute Redis commands on a password protected Redis server.",
    "Resource Type": "ReplicationGroup",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-0057-ACK
#

default cache_redis_encrypt = null

aws_issue["cache_redis_encrypt"] {
    resource := input.Resources[i]
    lower(resource.kind) == "replicationgroup"
    not resource.spec.atRestEncryptionEnabled
}

cache_redis_encrypt {
    lower(input.Resources[i].kind) == "replicationgroup"
    not aws_issue["cache_redis_encrypt"]
}

cache_redis_encrypt = false {
    aws_issue["cache_redis_encrypt"]
}

cache_redis_encrypt_err = "AWS ElastiCache Redis cluster with encryption for data at rest disabled" {
    aws_issue["cache_redis_encrypt"]
}

cache_redis_encrypt_metadata := {
    "Policy Code": "PR-AWS-0057-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS ElastiCache Redis cluster with encryption for data at rest disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have encryption for data at rest(at-rest) is disabled. It is highly recommended to implement at-rest encryption in order to prevent unauthorized users from reading sensitive data saved to persistent media available on your Redis clusters and their associated cache storage systems.",
    "Resource Type": "ReplicationGroup",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}

#
# PR-AWS-0058-ACK
#

default cache_encrypt = null

aws_issue["cache_encrypt"] {
    lower(input.kind) == "replicationgroup"
    not input.spec.atRestEncryptionEnabled
}

cache_encrypt {
    lower(input.kind) == "replicationgroup"
    not aws_issue["cache_encrypt"]
}

cache_encrypt = false {
    aws_issue["cache_encrypt"]
}

cache_encrypt_err = "AWS ElastiCache Redis cluster with in-transit encryption disabled" {
    aws_issue["cache_encrypt"]
}

cache_encrypt_metadata := {
    "Policy Code": "PR-AWS-0058-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS ElastiCache Redis cluster with in-transit encryption disabled",
    "Policy Description": "This policy identifies ElastiCache Redis clusters which have in-transit encryption disabled. It is highly recommended to implement in-transit encryption in order to protect data from unauthorized access as it travels through the network, between clients and cache servers. Enabling data encryption in-transit helps prevent unauthorized users from reading sensitive data between your Redis clusters and their associated cache storage systems.",
    "Resource Type": "ReplicationGroup",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticache-replicationgroup.html"
}
