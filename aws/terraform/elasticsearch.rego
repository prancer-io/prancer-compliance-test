package rule


#
# PR-AWS-TRF-ES-001
#

default esearch_vpc = null

aws_attribute_absence["esearch_vpc"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    not resource.properties.vpc_options
}

aws_attribute_absence["esearch_vpc"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    count(resource.properties.vpc_options) == 0
}

aws_issue["esearch_vpc"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    vpc_options := resource.properties.vpc_options[_]
    count([ c | vpc_options.subnet_ids != ""; c = 1]) == 0
}

esearch_vpc {
    lower(input.resources[_].type) == "aws_elasticsearch_domain"
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
} else = "Elasticsearch attribute vpc_options.subnet_ids missing in the resource" {
    aws_attribute_absence["esearch_vpc"]
}

esearch_vpc_metadata := {
    "Policy Code": "PR-AWS-TRF-ES-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ElasticSearch cluster not in a VPC",
    "Policy Description": "VPC support for Amazon ES is easy to configure, reliable, and offers an extra layer of security. With VPC support, traffic between other services and Amazon ES stays entirely within the AWS network, isolated from the public Internet. You can manage network access using existing VPC security groups, and you can use AWS Identity and Access Management (IAM) policies for additional protection. VPC support for Amazon ES domains is available at no additional charge.",
    "Resource Type": "aws_elasticsearch_domain",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-TRF-ES-002
#

default esearch_encrypt = null

aws_attribute_absence["esearch_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    not resource.properties.encrypt_at_rest
}

aws_issue["esearch_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    count(resource.properties.encrypt_at_rest) == 0
}

aws_issue["esearch_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    encrypt_at_rest := resource.properties.encrypt_at_rest[_]
    lower(encrypt_at_rest.enabled) == "false"
}

aws_bool_issue["esearch_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    encrypt_at_rest := resource.properties.encrypt_at_rest[_]
    not encrypt_at_rest.enabled
}

esearch_encrypt {
    lower(input.resources[_].type) == "aws_elasticsearch_domain"
    not aws_issue["esearch_encrypt"]
    not aws_bool_issue["esearch_encrypt"]
    not aws_attribute_absence["esearch_encrypt"]
}

esearch_encrypt = false {
    aws_issue["esearch_encrypt"]
}

esearch_encrypt = false {
    aws_bool_issue["esearch_encrypt"]
}

esearch_encrypt = false {
    aws_attribute_absence["esearch_encrypt"]
}

esearch_encrypt_err = "AWS Elasticsearch domain Encryption for data at rest is disabled" {
    aws_issue["esearch_encrypt"]
} else = "AWS Elasticsearch domain Encryption for data at rest is disabled" {
    aws_bool_issue["esearch_encrypt"]
} else = "AWS Elasticsearch domain Encryption for data missing" {
    aws_attribute_absence["esearch_encrypt"]
}

esearch_encrypt_metadata := {
    "Policy Code": "PR-AWS-TRF-ES-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elasticsearch domain Encryption for data at rest is disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which encryption is disabled. Encryption of data at rest is required to prevent unauthorized users from accessing the sensitive information available on your Elasticsearch domains components. This may include all data of file systems, primary and replica indices, log files, memory swap files and automated snapshots. The Elasticsearch uses AWS KMS service to store and manage the encryption keys. It is highly recommended to implement encryption at rest when you are working with production data that have sensitive information, to protect from unauthorized access.",
    "Resource Type": "aws_elasticsearch_domain",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-TRF-ES-003
#

default esearch_master = null

aws_issue["esearch_master"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    count(resource.properties.cluster_config) == 0
}

aws_issue["esearch_master"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    cluster_config := resource.properties.cluster_config[_]
    lower(cluster_config.dedicated_master_enabled) == "false"
}

aws_bool_issue["esearch_master"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    cluster_config := resource.properties.cluster_config[_]
    not cluster_config.dedicated_master_enabled
}

esearch_master {
    lower(input.resources[_].type) == "aws_elasticsearch_domain"
    not aws_issue["esearch_master"]
    not aws_bool_issue["esearch_master"]
}

esearch_master = false {
    aws_issue["esearch_master"]
}

esearch_master = false {
    aws_bool_issue["esearch_master"]
}

esearch_master_err = "AWS Elasticsearch domain has Dedicated master set to disabled" {
    aws_issue["esearch_master"]
} else = "AWS Elasticsearch domain has Dedicated master set to disabled" {
    aws_bool_issue["esearch_master"]
}

esearch_master_metadata := {
    "Policy Code": "PR-AWS-TRF-ES-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elasticsearch domain has Dedicated master set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Dedicated master is disabled in your AWS account. If dedicated master nodes are provided those handle the management tasks and cluster nodes can easily manage index and search requests from different types of workload and make them more resilient in production. Dedicated master nodes improve environmental stability by freeing all the management tasks from the cluster data nodes.",
    "Resource Type": "aws_elasticsearch_domain",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-TRF-ES-004
#

default esearch_index_slow_log = null

aws_attribute_absence["esearch_index_slow_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    not resource.properties.log_publishing_options
}

aws_issue["esearch_index_slow_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    logs := resource.properties.log_publishing_options[_]
    logs.log_type == "INDEX_SLOW_LOGS"
    lower(logs.enabled) == "false"
}

aws_bool_issue["esearch_index_slow_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    logs := resource.properties.log_publishing_options[_]
    logs.log_type == "INDEX_SLOW_LOGS"
    logs.enabled == false
}

aws_issue["esearch_index_slow_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    log_publishing_options := resource.properties.log_publishing_options[_]
    count([ c | log_publishing_options.log_type == "INDEX_SLOW_LOGS"; c = 1]) == 0
}

esearch_index_slow_log {
    lower(input.resources[_].type) == "aws_elasticsearch_domain"
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
} else = "Elasticsearch attribute log_publishing_options missing in the resource" {
    aws_attribute_absence["esearch_index_slow_log"]
}

esearch_index_slow_log_metadata := {
    "Policy Code": "PR-AWS-TRF-ES-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elasticsearch domain has Index slow logs set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Index slow logs is disabled in your AWS account. Enabling support for publishing indexing slow logs to AWS CloudWatch Logs enables you have full insight into the performance of indexing operations performed on your Elasticsearch clusters. This will help you in identifying performance issues caused by specific queries or due to changes in cluster usage, so that you can optimize your index configuration to address the problem.",
    "Resource Type": "aws_elasticsearch_domain",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-TRF-ES-005
#

default esearch_search_slow_log = null

aws_attribute_absence["esearch_search_slow_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    not resource.properties.log_publishing_options
}

aws_issue["esearch_search_slow_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    logs := resource.properties.log_publishing_options[_]
    logs.log_type == "SEARCH_SLOW_LOGS"
    lower(logs.enabled) == "false"
}

aws_bool_issue["esearch_search_slow_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    logs := resource.properties.log_publishing_options[_]
    logs.log_type == "SEARCH_SLOW_LOGS"
    logs.enabled == false
}

aws_issue["esearch_search_slow_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    log_publishing_options := resource.properties.log_publishing_options[_]
    count([ c | log_publishing_options.log_type == "SEARCH_SLOW_LOGS"; c = 1]) == 0
}

esearch_search_slow_log {
    lower(input.resources[_].type) == "aws_elasticsearch_domain"
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
} else = "Elasticsearch attribute log_publishing_options missing in the resource" {
    aws_attribute_absence["esearch_search_slow_log"]
}

esearch_search_slow_log_metadata := {
    "Policy Code": "PR-AWS-TRF-ES-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elasticsearch domain has Search slow logs set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Search slow logs is disabled in your AWS account. Enabling support for publishing Search slow logs to AWS CloudWatch Logs enables you to have full insight into the performance of search operations performed on your Elasticsearch clusters. This will help you in identifying performance issues caused by specific search queries so that you can optimize your queries to address the problem.",
    "Resource Type": "aws_elasticsearch_domain",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-TRF-ES-006
#

default esearch_zone_awareness = null

aws_issue["esearch_zone_awareness"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    cluster_config := resource.properties.cluster_config[_]
    lower(cluster_config.zone_awareness_enabled) == "false"
}

aws_bool_issue["esearch_zone_awareness"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    cluster_config := resource.properties.cluster_config[_]
    not cluster_config.zone_awareness_enabled
}

esearch_zone_awareness {
    lower(input.resources[_].type) == "aws_elasticsearch_domain"
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
    "Policy Code": "PR-AWS-TRF-ES-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elasticsearch domain has Zone Awareness set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Zone Awareness is disabled in your AWS account. Enabling Zone Awareness (cross-zone replication) increases the availability by distributing your Elasticsearch data nodes across two availability zones available in the same AWS region. It also prevents data loss and minimizes downtime in the event of node or availability zone failure.",
    "Resource Type": "aws_elasticsearch_domain",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-TRF-ES-007
#

default esearch_node_encryption = null

aws_issue["esearch_node_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticsearch_domain"
    node_to_node_encryption := resource.properties.node_to_node_encryption[_]
    lower(node_to_node_encryption.enabled) == "false"
}

aws_bool_issue["esearch_node_encryption"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticsearch_domain"
    node_to_node_encryption := resource.properties.node_to_node_encryption[_]
    not node_to_node_encryption.enabled
}

esearch_node_encryption {
    lower(input.resources[i].type) == "aws_elasticsearch_domain"
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
    "Policy Code": "PR-AWS-TRF-ES-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure node-to-node encryption is enabled on each ElasticSearch Domain",
    "Policy Description": "Ensure that node-to-node encryption feature is enabled for your AWS ElasticSearch domains (clusters) in order to add an extra layer of data protection on top of the existing ES security features such as HTTPS client to cluster encryption and data-at-rest encryption, and meet strict compliance requirements. The ElasticSearch node-to-node encryption capability provides the additional layer of security by implementing Transport Layer Security (TLS) for all communications between the nodes provisioned within the cluster. The feature ensures that any data sent to your AWS ElasticSearch domain over HTTPS remains encrypted in transit while it is being distributed and replicated between the nodes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-node_to_node_encryption"
}

#
# PR-AWS-TRF-ES-008
#

default esearch_enforce_https = null

aws_issue["esearch_enforce_https"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticsearch_domain"
    domain_endpoint_options := resource.properties.domain_endpoint_options[_]
    lower(domain_endpoint_options.enforce_https) == "false"
}

aws_bool_issue["esearch_enforce_https"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticsearch_domain"
    domain_endpoint_options := resource.properties.domain_endpoint_options[_]
    not domain_endpoint_options.enforce_https
}

esearch_enforce_https {
    lower(input.resources[i].type) == "aws_elasticsearch_domain"
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
    "Policy Code": "PR-AWS-TRF-ES-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elasticsearch domain is not configured with HTTPS",
    "Policy Description": "This policy identifies Elasticsearch domains that are not configured with HTTPS. Amazon Elasticsearch domains allow all traffic to be submitted over HTTPS, ensuring all communications between application and domain are encrypted. It is recommended to enable HTTPS so that all communication between the application and all data access goes across an encrypted communication channel to eliminate man-in-the-middle attacks",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domain_endpoint_options.html#cfn-elasticsearch-domain-domain_endpoint_options-enforce_https"
}

#
# PR-AWS-TRF-ES-009
#

default esearch_encrypt_kms = null

aws_issue["esearch_encrypt_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticsearch_domain"
    encrypt_at_rest := resource.properties.encrypt_at_rest[_]
    lower(encrypt_at_rest.enabled) == "true"
    not encrypt_at_rest.kms_key_id
}

aws_issue["esearch_encrypt_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticsearch_domain"
    encrypt_at_rest := resource.properties.encrypt_at_rest[_]
    lower(encrypt_at_rest.enabled) == "true"
    lower(encrypt_at_rest.kms_key_id) == ""
}

aws_bool_issue["esearch_encrypt_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticsearch_domain"
    encrypt_at_rest := resource.properties.encrypt_at_rest[_]
    encrypt_at_rest.enabled == true
    not encrypt_at_rest.kms_key_id
}

aws_bool_issue["esearch_encrypt_kms"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elasticsearch_domain"
    encrypt_at_rest := resource.properties.encrypt_at_rest[_]
    encrypt_at_rest.enabled == true
    lower(encrypt_at_rest.kms_key_id) == ""
}


esearch_encrypt_kms {
    lower(input.resources[i].type) == "aws_elasticsearch_domain"
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
    "Policy Code": "PR-AWS-TRF-ES-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Elasticsearch Domain should not have Encrytion using AWS Managed Keys",
    "Policy Description": "Ensure that your Amazon ElasticSearch (ES) domains are encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys (default keys used by the ES service when there are no customer keys defined) in order to have more granular control over the data-at-rest encryption/decryption process and to meet compliance requirements.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}