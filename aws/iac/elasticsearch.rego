package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html

#
# PR-AWS-CFR-ES-001
#

default esearch_vpc = null

aws_attribute_absence["esearch_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.VPCOptions.SubnetIds
}

source_path[{"esearch_vpc": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.VPCOptions.SubnetIds
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "VPCOptions", "SubnetIds"]
        ],
    }
}

aws_issue["esearch_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.VPCOptions.SubnetIds) == 0
}

source_path[{"esearch_vpc": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.VPCOptions.SubnetIds) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "VPCOptions", "SubnetIds"]
        ],
    }
}

esearch_vpc {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_vpc"]
    not aws_attribute_absence["esearch_vpc"]
}

esearch_vpc = false {
    aws_issue["esearch_vpc"]
}

esearch_vpc = false {
    aws_attribute_absence["esearch_vpc"]
}

esearch_vpc_err = "AWS ElasticSearch cluster not in a VPC" {
    aws_issue["esearch_vpc"]
}

esearch_vpc_miss_err = "Elasticsearch attribute VPCOptions.SubnetIds missing in the resource" {
    aws_attribute_absence["esearch_vpc"]
}

esearch_vpc_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ElasticSearch cluster not in a VPC",
    "Policy Description": "VPC support for Amazon ES is easy to configure, reliable, and offers an extra layer of security. With VPC support, traffic between other services and Amazon ES stays entirely within the AWS network, isolated from the public Internet. You can manage network access using existing VPC security groups, and you can use AWS Identity and Access Management (IAM) policies for additional protection. VPC support for Amazon ES domains is available at no additional charge.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-CFR-ES-002
#

default esearch_encrypt = null

aws_issue["esearch_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.EncryptionAtRestOptions.Enabled) == "false"
}

source_path[{"esearch_encrypt": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.EncryptionAtRestOptions.Enabled) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionAtRestOptions", "Enabled"]
        ],
    }
}

aws_bool_issue["esearch_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.EncryptionAtRestOptions.Enabled
}

source_path[{"esearch_encrypt": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.EncryptionAtRestOptions.Enabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionAtRestOptions", "Enabled"]
        ],
    }
}

esearch_encrypt {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_encrypt"]
    not aws_bool_issue["esearch_encrypt"]
}

esearch_encrypt = false {
    aws_issue["esearch_encrypt"]
}

esearch_encrypt = false {
    aws_bool_issue["esearch_encrypt"]
}

esearch_encrypt_err = "AWS Elasticsearch domain Encryption for data at rest is disabled" {
    aws_issue["esearch_encrypt"]
} else = "AWS Elasticsearch domain Encryption for data at rest is disabled" {
    aws_bool_issue["esearch_encrypt"]
}


esearch_encrypt_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elasticsearch domain Encryption for data at rest is disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which encryption is disabled. Encryption of data at rest is required to prevent unauthorized users from accessing the sensitive information available on your Elasticsearch domains components. This may include all data of file systems, primary and replica indices, log files, memory swap files and automated snapshots. The Elasticsearch uses AWS KMS service to store and manage the encryption keys. It is highly recommended to implement encryption at rest when you are working with production data that have sensitive information, to protect from unauthorized access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-CFR-ES-003
#

default esearch_master = null

aws_issue["esearch_master"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.ElasticsearchClusterConfig.DedicatedMasterEnabled
}

source_path[{"esearch_master": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.ElasticsearchClusterConfig.DedicatedMasterEnabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ElasticsearchClusterConfig", "DedicatedMasterEnabled"]
        ],
    }
}

esearch_master {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_master"]
}

esearch_master = false {
    aws_issue["esearch_master"]
}

esearch_master_err = "AWS Elasticsearch domain has Dedicated master set to disabled" {
    aws_issue["esearch_master"]
}

esearch_master_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elasticsearch domain has Dedicated master set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Dedicated master is disabled in your AWS account. If dedicated master nodes are provided those handle the management tasks and cluster nodes can easily manage index and search requests from different types of workload and make them more resilient in production. Dedicated master nodes improve environmental stability by freeing all the management tasks from the cluster data nodes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-CFR-ES-004
#

default esearch_index_slow_log = null

aws_attribute_absence["esearch_index_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions
}

source_path[{"esearch_index_slow_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LogPublishingOptions"]
        ],
    }
}

aws_issue["esearch_index_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled) == "false"
}

source_path[{"esearch_index_slow_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LogPublishingOptions", "INDEX_SLOW_LOGS", "Enabled"]
        ],
    }
}

aws_bool_issue["esearch_index_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled
}

source_path[{"esearch_index_slow_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LogPublishingOptions", "INDEX_SLOW_LOGS", "Enabled"]
        ],
    }
}

aws_issue["esearch_index_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn
}

source_path[{"esearch_index_slow_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LogPublishingOptions", "INDEX_SLOW_LOGS", "CloudWatchLogsLogGroupArn"]
        ],
    }
}

aws_issue["esearch_index_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn) == 0
}

source_path[{"esearch_index_slow_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LogPublishingOptions", "INDEX_SLOW_LOGS", "CloudWatchLogsLogGroupArn"]
        ],
    }
}

esearch_index_slow_log {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_index_slow_log"]
    not aws_bool_issue["esearch_index_slow_log"]
    not aws_attribute_absence["esearch_index_slow_log"]
}

esearch_index_slow_log = false {
    aws_issue["esearch_index_slow_log"]
}

esearch_index_slow_log = false {
    aws_bool_issue["esearch_index_slow_log"]
}

esearch_index_slow_log = false {
    aws_attribute_absence["esearch_index_slow_log"]
}

esearch_index_slow_log_err = "AWS Elasticsearch domain has Index slow logs set to disabled" {
    aws_issue["esearch_index_slow_log"]
} else = "AWS Elasticsearch domain has Index slow logs set to disabled" {
    aws_bool_issue["esearch_index_slow_log"]
}

esearch_index_slow_log_miss_err = "Elasticsearch attribute LogPublishingOptions missing in the resource" {
    aws_attribute_absence["esearch_index_slow_log"]
}

esearch_index_slow_log_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elasticsearch domain has Index slow logs set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Index slow logs is disabled in your AWS account. Enabling support for publishing indexing slow logs to AWS CloudWatch Logs enables you have full insight into the performance of indexing operations performed on your Elasticsearch clusters. This will help you in identifying performance issues caused by specific queries or due to changes in cluster usage, so that you can optimize your index configuration to address the problem.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-CFR-ES-005
#

default esearch_search_slow_log = null

aws_attribute_absence["esearch_search_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions
}

source_path[{"esearch_search_slow_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LogPublishingOptions"]
        ],
    }
}

aws_issue["esearch_search_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled) == "false"
}

source_path[{"esearch_search_slow_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LogPublishingOptions", "SEARCH_SLOW_LOGS", "Enabled"]
        ],
    }
}

aws_bool_issue["esearch_search_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled
}

source_path[{"esearch_search_slow_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LogPublishingOptions", "SEARCH_SLOW_LOGS", "Enabled"]
        ],
    }
}

aws_issue["esearch_search_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn
}

source_path[{"esearch_search_slow_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LogPublishingOptions", "SEARCH_SLOW_LOGS", "CloudWatchLogsLogGroupArn"]
        ],
    }
}

aws_issue["esearch_search_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn) == 0
}

source_path[{"esearch_search_slow_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LogPublishingOptions", "SEARCH_SLOW_LOGS", "CloudWatchLogsLogGroupArn"]
        ],
    }
}

esearch_search_slow_log {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_search_slow_log"]
    not aws_bool_issue["esearch_search_slow_log"]
    not aws_attribute_absence["esearch_search_slow_log"]
}

esearch_search_slow_log = false {
    aws_issue["esearch_search_slow_log"]
}

esearch_search_slow_log = false {
    aws_bool_issue["esearch_search_slow_log"]
}

esearch_search_slow_log = false {
    aws_attribute_absence["esearch_search_slow_log"]
}

esearch_search_slow_log_err = "AWS Elasticsearch domain has Search slow logs set to disabled" {
    aws_issue["esearch_search_slow_log"]
} else = "AWS Elasticsearch domain has Search slow logs set to disabled" {
    aws_bool_issue["esearch_search_slow_log"]
}

esearch_search_slow_log_miss_err = "Elasticsearch attribute LogPublishingOptions missing in the resource" {
    aws_attribute_absence["esearch_search_slow_log"]
}

esearch_search_slow_log_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elasticsearch domain has Search slow logs set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Search slow logs is disabled in your AWS account. Enabling support for publishing Search slow logs to AWS CloudWatch Logs enables you to have full insight into the performance of search operations performed on your Elasticsearch clusters. This will help you in identifying performance issues caused by specific search queries so that you can optimize your queries to address the problem.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-CFR-ES-006
#

default esearch_zone_awareness = null

aws_issue["esearch_zone_awareness"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled) == "false"
}

source_path[{"esearch_zone_awareness": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ElasticsearchClusterConfig", "ZoneAwarenessEnabled"]
        ],
    }
}

aws_bool_issue["esearch_zone_awareness"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled
}

source_path[{"esearch_zone_awareness": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ElasticsearchClusterConfig", "ZoneAwarenessEnabled"]
        ],
    }
}

esearch_zone_awareness {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_zone_awareness"]
    not aws_bool_issue["esearch_zone_awareness"]
}

esearch_zone_awareness = false {
    aws_issue["esearch_zone_awareness"]
}

esearch_zone_awareness = false {
    aws_bool_issue["esearch_zone_awareness"]
}

esearch_zone_awareness_err = "AWS Elasticsearch domain has Zone Awareness set to disabled" {
    aws_issue["esearch_zone_awareness"]
} else = "AWS Elasticsearch domain has Zone Awareness set to disabled" {
    aws_bool_issue["esearch_zone_awareness"]
}

esearch_zone_awareness_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elasticsearch domain has Zone Awareness set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Zone Awareness is disabled in your AWS account. Enabling Zone Awareness (cross-zone replication) increases the availability by distributing your Elasticsearch data nodes across two availability zones available in the same AWS region. It also prevents data loss and minimizes downtime in the event of node or availability zone failure.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}


#
# PR-AWS-CFR-ES-007
#

default esearch_node_encryption = null

aws_issue["esearch_node_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.NodeToNodeEncryptionOptions.Enabled) == "false"
}

source_path[{"esearch_node_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.NodeToNodeEncryptionOptions.Enabled) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NodeToNodeEncryptionOptions", "Enabled"]
        ],
    }
}

aws_bool_issue["esearch_node_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.NodeToNodeEncryptionOptions.Enabled
}

source_path[{"esearch_node_encryption": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.NodeToNodeEncryptionOptions.Enabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NodeToNodeEncryptionOptions", "Enabled"]
        ],
    }
}

esearch_node_encryption {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_node_encryption"]
    not aws_bool_issue["esearch_node_encryption"]
}

esearch_node_encryption = false {
    aws_issue["esearch_node_encryption"]
}

esearch_node_encryption = false {
    aws_bool_issue["esearch_node_encryption"]
}

esearch_node_encryption_err = "Ensure node-to-node encryption is enabled on each ElasticSearch Domain" {
    aws_issue["esearch_node_encryption"]
} else = "Ensure node-to-node encryption is enabled on each ElasticSearch Domain" {
    aws_bool_issue["esearch_node_encryption"]
}

esearch_node_encryption_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure node-to-node encryption is enabled on each ElasticSearch Domain",
    "Policy Description": "Ensure that node-to-node encryption feature is enabled for your AWS ElasticSearch domains (clusters) in order to add an extra layer of data protection on top of the existing ES security features such as HTTPS client to cluster encryption and data-at-rest encryption, and meet strict compliance requirements. The ElasticSearch node-to-node encryption capability provides the additional layer of security by implementing Transport Layer Security (TLS) for all communications between the nodes provisioned within the cluster. The feature ensures that any data sent to your AWS ElasticSearch domain over HTTPS remains encrypted in transit while it is being distributed and replicated between the nodes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-nodetonodeencryptionoptions"
}


#
# PR-AWS-CFR-ES-008
#

default esearch_enforce_https = null

aws_issue["esearch_enforce_https"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.DomainEndpointOptions.EnforceHTTPS) == "false"
}

source_path[{"esearch_enforce_https": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.DomainEndpointOptions.EnforceHTTPS) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NodeToNodeEncryptionOptions", "EnforceHTTPS"]
        ],
    }
}

aws_bool_issue["esearch_enforce_https"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.DomainEndpointOptions.EnforceHTTPS
}

source_path[{"esearch_enforce_https": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.DomainEndpointOptions.EnforceHTTPS
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "NodeToNodeEncryptionOptions", "EnforceHTTPS"]
        ],
    }
}

esearch_enforce_https {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_enforce_https"]
    not aws_bool_issue["esearch_enforce_https"]
}

esearch_enforce_https = false {
    aws_issue["esearch_enforce_https"]
}

esearch_enforce_https = false {
    aws_bool_issue["esearch_enforce_https"]
}

esearch_enforce_https_err = "AWS Elasticsearch domain is not configured with HTTPS" {
    aws_issue["esearch_enforce_https"]
} else = "AWS Elasticsearch domain is not configured with HTTPS" {
    aws_bool_issue["esearch_enforce_https"]
}

esearch_enforce_https_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elasticsearch domain is not configured with HTTPS",
    "Policy Description": "This policy identifies Elasticsearch domains that are not configured with HTTPS. Amazon Elasticsearch domains allow all traffic to be submitted over HTTPS, ensuring all communications between application and domain are encrypted. It is recommended to enable HTTPS so that all communication between the application and all data access goes across an encrypted communication channel to eliminate man-in-the-middle attacks",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html#cfn-elasticsearch-domain-domainendpointoptions-enforcehttps"
}


#
# PR-AWS-CFR-ES-009
#

default esearch_encrypt_kms = null

aws_issue["esearch_encrypt_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.EncryptionAtRestOptions.Enabled) == "true"
    not resource.Properties.EncryptionAtRestOptions.KmsKeyId
}

source_path[{"esearch_encrypt_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.EncryptionAtRestOptions.Enabled) == "true"
    not resource.Properties.EncryptionAtRestOptions.KmsKeyId
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionAtRestOptions", "KmsKeyId"]
        ],
    }
}

aws_issue["esearch_encrypt_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.EncryptionAtRestOptions.Enabled) == "true"
    count(resource.Properties.EncryptionAtRestOptions.KmsKeyId) == 0
}

source_path[{"esearch_encrypt_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.EncryptionAtRestOptions.Enabled) == "true"
    count(resource.Properties.EncryptionAtRestOptions.KmsKeyId) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionAtRestOptions", "KmsKeyId"]
        ],
    }
}

aws_bool_issue["esearch_encrypt_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    resource.Properties.EncryptionAtRestOptions.Enabled
    not resource.Properties.EncryptionAtRestOptions.KmsKeyId
}

source_path[{"esearch_encrypt_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    resource.Properties.EncryptionAtRestOptions.Enabled
    not resource.Properties.EncryptionAtRestOptions.KmsKeyId
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionAtRestOptions", "KmsKeyId"]
        ],
    }
}

aws_bool_issue["esearch_encrypt_kms"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    resource.Properties.EncryptionAtRestOptions.Enabled
    count(resource.Properties.EncryptionAtRestOptions.KmsKeyId) == 0
}

source_path[{"esearch_encrypt_kms": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    resource.Properties.EncryptionAtRestOptions.Enabled
    count(resource.Properties.EncryptionAtRestOptions.KmsKeyId) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "EncryptionAtRestOptions", "KmsKeyId"]
        ],
    }
}

esearch_encrypt_kms {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_encrypt_kms"]
    not aws_bool_issue["esearch_encrypt_kms"]
}

esearch_encrypt_kms = false {
    aws_issue["esearch_encrypt_kms"]
}

esearch_encrypt_kms = false {
    aws_bool_issue["esearch_encrypt_kms"]
}

esearch_encrypt_kms_err = "Elasticsearch Domain should not have Encrytion using AWS Managed Keys" {
    aws_issue["esearch_encrypt_kms"]
} else = "Elasticsearch Domain should not have Encrytion using AWS Managed Keys" {
    aws_bool_issue["esearch_encrypt_kms"]
}


esearch_encrypt_kms_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Elasticsearch Domain should not have Encrytion using AWS Managed Keys",
    "Policy Description": "Ensure that your Amazon ElasticSearch (ES) domains are encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys (default keys used by the ES service when there are no customer keys defined) in order to have more granular control over the data-at-rest encryption/decryption process and to meet compliance requirements.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}


#
# PR-AWS-CFR-ES-010
#

default esearch_custom_endpoint_configured = null

aws_issue["esearch_custom_endpoint_configured"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.DomainEndpointOptions.CustomEndpointEnabled
}

esearch_custom_endpoint_configured {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_custom_endpoint_configured"]
}

esearch_custom_endpoint_configured = false {
    aws_issue["esearch_custom_endpoint_configured"]
}

esearch_custom_endpoint_configured_err = "Ensure ElasticSearch has a custom endpoint configured." {
    aws_issue["esearch_custom_endpoint_configured"]
}

esearch_custom_endpoint_configured_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure ElasticSearch has a custom endpoint configured.",
    "Policy Description": "It checks if a default endpoint is configured for ES domain.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}


#
# PR-AWS-CFR-ES-011
#

default esearch_slow_logs_is_enabled = null

aws_issue["esearch_slow_logs_is_enabled"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled
}

aws_issue["authentication_is_saml_based"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled
}

esearch_slow_logs_is_enabled {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_slow_logs_is_enabled"]
}

esearch_slow_logs_is_enabled = false {
    aws_issue["esearch_slow_logs_is_enabled"]
}

esearch_slow_logs_is_enabled_err = "Ensure Slow Logs feature is enabled for ElasticSearch cluster." {
    aws_issue["esearch_slow_logs_is_enabled"]
}

esearch_slow_logs_is_enabled_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Slow Logs feature is enabled for ElasticSearch cluster.",
    "Policy Description": "It checks of slow logs is enabled for the ES cluster. Slow logs provide valuable information for optimizing and troubleshooting your search and indexing operations.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}


#
# PR-AWS-CFR-ES-013
#

default fine_grained_encryption_for_elasticsearch = null

aws_issue["fine_grained_encryption_for_elasticsearch"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.EncryptionAtRestOptions.Enabled
}

aws_issue["fine_grained_encryption_for_elasticsearch"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.DomainEndpointOptions.EnforceHTTPS
}

aws_issue["fine_grained_encryption_for_elasticsearch"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.NodeToNodeEncryptionOptions.Enabled
}

fine_grained_encryption_for_elasticsearch {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["fine_grained_encryption_for_elasticsearch"]
}

fine_grained_encryption_for_elasticsearch = false {
    aws_issue["fine_grained_encryption_for_elasticsearch"]
}

fine_grained_encryption_for_elasticsearch_err = "Ensure fine-grained access control is enabled during domain creation in ElasticSearch." {
    aws_issue["fine_grained_encryption_for_elasticsearch"]
}

fine_grained_encryption_for_elasticsearch_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure fine-grained access control is enabled during domain creation in ElasticSearch.",
    "Policy Description": "It checks if fine grained access controls is enabled for the ElasticSearch cluster and node to node encryption is enabled with it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}


#
# PR-AWS-CFR-ES-017
#

default es_advanced_security = null

aws_issue["es_advanced_security"] {
    resource := input.Resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.AdvancedSecurityOptions.Enabled
    not resource.Properties.AdvancedSecurityOptions.InternalUserDatabaseEnabled
}

es_advanced_security = false {
    aws_issue["es_advanced_security"]
}

es_advanced_security {
    lower(input.Resources[_].Type) == "aws::elasticsearch::domain"
    not aws_issue["es_advanced_security"]
}

es_advanced_security_err = "Ensure AWS OpenSearch Fine-grained access control is enabled." {
    aws_issue["es_advanced_security"]
}

es_advanced_security_metadata := {
    "Policy Code": "PR-AWS-CFR-ES-017",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS OpenSearch Fine-grained access control is enabled.",
    "Policy Description": "It identifies AWS OpenSearch which has Fine-grained access control disabled. Fine-grained access control offers additional ways of controlling access to your data on AWS OpenSearch Service. It is highly recommended enabling fine-grained access control to protect the data on your domain. For more information, please follow the URL given below,https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}