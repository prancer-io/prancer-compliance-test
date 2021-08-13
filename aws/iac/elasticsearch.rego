package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html

#
# PR-AWS-0074-CFR
#

default esearch_vpc = null

aws_attribute_absence["esearch_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.VPCOptions.SubnetIds
}

aws_issue["esearch_vpc"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.VPCOptions.SubnetIds) == 0
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
    "Policy Code": "PR-AWS-0074-CFR",
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
# PR-AWS-0076-CFR
#

default esearch_encrypt = null

aws_issue["esearch_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.EncryptionAtRestOptions.Enabled) == "false"
}

aws_bool_issue["esearch_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.EncryptionAtRestOptions.Enabled
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
    "Policy Code": "PR-AWS-0076-CFR",
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
# PR-AWS-0077-CFR
#

default esearch_master = null

aws_issue["esearch_master"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.ElasticsearchClusterConfig.DedicatedMasterEnabled
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
    "Policy Code": "PR-AWS-0077-CFR",
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
# PR-AWS-0078-CFR
#

default esearch_index_slow_log = null

aws_attribute_absence["esearch_index_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions
}

aws_issue["esearch_index_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled) == "false"
}

aws_bool_issue["esearch_index_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled
}

aws_issue["esearch_index_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn
}

aws_issue["esearch_index_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn) == 0
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
    "Policy Code": "PR-AWS-0078-CFR",
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
# PR-AWS-0079-CFR
#

default esearch_search_slow_log = null

aws_attribute_absence["esearch_search_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions
}

aws_issue["esearch_search_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled) == "false"
}

aws_bool_issue["esearch_search_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled
}

aws_issue["esearch_search_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn
}

aws_issue["esearch_search_slow_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn) == 0
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
    "Policy Code": "PR-AWS-0079-CFR",
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
# PR-AWS-0080-CFR
#

default esearch_zone_awareness = null

aws_issue["esearch_zone_awareness"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled) == "false"
}

aws_bool_issue["esearch_zone_awareness"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled
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
    "Policy Code": "PR-AWS-0080-CFR",
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
# PR-AWS-0216-CFR
#

default esearch_node_encryption = null

aws_issue["esearch_node_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    lower(resource.Properties.NodeToNodeEncryptionOptions.Enabled) == "false"
}

aws_bool_issue["esearch_node_encryption"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.NodeToNodeEncryptionOptions.Enabled
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
    "Policy Code": "PR-AWS-0216-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure node-to-node encryption is enabled on each ElasticSearch Domain",
    "Policy Description": "Ensure that node-to-node encryption feature is enabled for your AWS ElasticSearch domains (clusters) in order to add an extra layer of data protection on top of the existing ES security features such as HTTPS client to cluster encryption and data-at-rest encryption, and meet strict compliance requirements. The ElasticSearch node-to-node encryption capability provides the additional layer of security by implementing Transport Layer Security (TLS) for all communications between the nodes provisioned within the cluster. The feature ensures that any data sent to your AWS ElasticSearch domain over HTTPS remains encrypted in transit while it is being distributed and replicated between the nodes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-nodetonodeencryptionoptions"
}
