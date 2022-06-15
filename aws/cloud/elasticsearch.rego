package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html

available_true_choices := ["true", true]
available_false_choices := ["false", false]

#
# PR-AWS-CLD-ES-001
#

default esearch_vpc = false

esearch_vpc = true {
    # lower(resource.Type) == "aws::elasticsearch::domain"
    count(input.DomainStatus.VPCOptions.SubnetIds) != 0
}

esearch_vpc_err = "AWS ElasticSearch cluster not in a VPC" {
    not esearch_vpc
}

esearch_vpc_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ElasticSearch cluster not in a VPC",
    "Policy Description": "VPC support for Amazon ES is easy to configure, reliable, and offers an extra layer of security. With VPC support, traffic between other services and Amazon ES stays entirely within the AWS network, isolated from the public Internet. You can manage network access using existing VPC security groups, and you can use AWS Identity and Access Management (IAM) policies for additional protection. VPC support for Amazon ES domains is available at no additional charge.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-CLD-ES-002
#

default esearch_encrypt = false

esearch_encrypt = true {
    # lower(resource.Type) == "aws::elasticsearch::domain"
    input.DomainStatus.EncryptionAtRestOptions.Enabled == true
}

esearch_encrypt_err = "AWS Elasticsearch domain Encryption for data at rest is disabled" {
    not esearch_encrypt
}

esearch_encrypt_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elasticsearch domain Encryption for data at rest is disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which encryption is disabled. Encryption of data at rest is required to prevent unauthorized users from accessing the sensitive information available on your Elasticsearch domains components. This may include all data of file systems, primary and replica indices, log files, memory swap files and automated snapshots. The Elasticsearch uses AWS KMS service to store and manage the encryption keys. It is highly recommended to implement encryption at rest when you are working with production data that have sensitive information, to protect from unauthorized access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}


#
# PR-AWS-CLD-ES-003
#

default esearch_master = false

esearch_master = true {
    # lower(resource.Type) == "aws::elasticsearch::domain"
    input.DomainStatus.ElasticsearchClusterConfig.DedicatedMasterEnabled == true
}

esearch_master_err = "AWS Elasticsearch domain has Dedicated master set to disabled" {
    not esearch_master
}

esearch_master_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elasticsearch domain has Dedicated master set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Dedicated master is disabled in your AWS account. If dedicated master nodes are provided those handle the management tasks and cluster nodes can easily manage index and search requests from different types of workload and make them more resilient in production. Dedicated master nodes improve environmental stability by freeing all the management tasks from the cluster data nodes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}


#
# PR-AWS-CLD-ES-004
#

default esearch_index_slow_log = false

esearch_index_slow_log = true {
    # lower(resource.Type) == "aws::elasticsearch::domain"
    count(input.DomainStatus.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn) != 0
}

esearch_index_slow_log_err = "AWS Elasticsearch domain has Index slow logs set to disabled" {
    not esearch_index_slow_log
}

esearch_index_slow_log_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elasticsearch domain has Index slow logs set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Index slow logs is disabled in your AWS account. Enabling support for publishing indexing slow logs to AWS CloudWatch Logs enables you have full insight into the performance of indexing operations performed on your Elasticsearch clusters. This will help you in identifying performance issues caused by specific queries or due to changes in cluster usage, so that you can optimize your index configuration to address the problem.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-CLD-ES-005
#

default esearch_search_slow_log = false

esearch_search_slow_log = true {
    # lower(resource.Type) == "aws::elasticsearch::domain"
    count(input.DomainStatus.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn) != 0
}

esearch_search_slow_log_err = "AWS Elasticsearch domain has Search slow logs set to disabled" {
    not esearch_search_slow_log
}

esearch_search_slow_log_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elasticsearch domain has Search slow logs set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Search slow logs is disabled in your AWS account. Enabling support for publishing Search slow logs to AWS CloudWatch Logs enables you to have full insight into the performance of search operations performed on your Elasticsearch clusters. This will help you in identifying performance issues caused by specific search queries so that you can optimize your queries to address the problem.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-CLD-ES-006
#

default esearch_zone_awareness = false

esearch_zone_awareness = true {
    # lower(resource.Type) == "aws::elasticsearch::domain"
    input.DomainStatus.ElasticsearchClusterConfig.ZoneAwarenessEnabled == true
}

esearch_zone_awareness_err = "AWS Elasticsearch domain has Zone Awareness set to disabled" {
    not esearch_zone_awareness
}

esearch_zone_awareness_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elasticsearch domain has Zone Awareness set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Zone Awareness is disabled in your AWS account. Enabling Zone Awareness (cross-zone replication) increases the availability by distributing your Elasticsearch data nodes across two availability zones available in the same AWS region. It also prevents data loss and minimizes downtime in the event of node or availability zone failure.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}


#
# PR-AWS-CLD-ES-007
#

default esearch_node_encryption = false

esearch_node_encryption = true {
    # lower(resource.Type) == "aws::elasticsearch::domain"
    input.DomainStatus.NodeToNodeEncryptionOptions.Enabled == true
}

esearch_node_encryption_err = "Ensure node-to-node encryption is enabled on each ElasticSearch Domain" {
    not esearch_node_encryption
}

esearch_node_encryption_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure node-to-node encryption is enabled on each ElasticSearch Domain",
    "Policy Description": "Ensure that node-to-node encryption feature is enabled for your AWS ElasticSearch domains (clusters) in order to add an extra layer of data protection on top of the existing ES security features such as HTTPS client to cluster encryption and data-at-rest encryption, and meet strict compliance requirements. The ElasticSearch node-to-node encryption capability provides the additional layer of security by implementing Transport Layer Security (TLS) for all communications between the nodes provisioned within the cluster. The feature ensures that any data sent to your AWS ElasticSearch domain over HTTPS remains encrypted in transit while it is being distributed and replicated between the nodes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-nodetonodeencryptionoptions"
}

#
# PR-AWS-CLD-ES-008
#

default esearch_enforce_https = false

esearch_enforce_https = true {
    # lower(resource.Type) == "aws::elasticsearch::domain"
    input.DomainStatus.DomainEndpointOptions.EnforceHTTPS == true
}

esearch_enforce_https_err = "AWS Elasticsearch domain is not configured with HTTPS" {
    not esearch_enforce_https
}

esearch_enforce_https_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elasticsearch domain is not configured with HTTPS",
    "Policy Description": "This policy identifies Elasticsearch domains that are not configured with HTTPS. Amazon Elasticsearch domains allow all traffic to be submitted over HTTPS, ensuring all communications between application and domain are encrypted. It is recommended to enable HTTPS so that all communication between the application and all data access goes across an encrypted communication channel to eliminate man-in-the-middle attacks",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html#cfn-elasticsearch-domain-domainendpointoptions-enforcehttps"
}


#
# PR-AWS-CLD-ES-009
#

default esearch_encrypt_kms = false

esearch_encrypt_kms = true {
    # lower(resource.Type) == "aws::elasticsearch::domain"
    input.DomainStatus.EncryptionAtRestOptions.Enabled == true
    count(input.DomainStatus.EncryptionAtRestOptions.KmsKeyId) != 0
}

esearch_encrypt_kms_err = "Elasticsearch Domain should not have Encrytion using AWS Managed Keys" {
    not esearch_encrypt_kms
}

esearch_encrypt_kms_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Elasticsearch Domain should not have Encrytion using AWS Managed Keys",
    "Policy Description": "Ensure that your Amazon ElasticSearch (ES) domains are encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys (default keys used by the ES service when there are no customer keys defined) in order to have more granular control over the data-at-rest encryption/decryption process and to meet compliance requirements.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}


#
# PR-AWS-CLD-ES-010
# aws::elasticsearch::domain
#

default esearch_custom_endpoint_configured = true

esearch_custom_endpoint_configured = false {
    lower(input.DomainStatus.DomainEndpointOptions.CustomEndpointEnabled) == available_false_choices[_]
}

esearch_custom_endpoint_configured_err = "Ensure ElasticSearch has a custom endpoint configured." {
    not esearch_custom_endpoint_configured
}

esearch_custom_endpoint_configured_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-010",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure ElasticSearch has a custom endpoint configured.",
    "Policy Description": "It checks if a default endpoint is configured for ES domain.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain"
}


#
# PR-AWS-CLD-ES-011
# aws::elasticsearch::domain
#

default esearch_slow_logs_is_enabled  = true

esearch_slow_logs_is_enabled = false {
    lower(input.DomainStatus.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled) == available_false_choices[_]
}

esearch_slow_logs_is_enabled = false {
    lower(input.DomainStatus.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled) == available_false_choices[_]
}

esearch_slow_logs_is_enabled_err = "Ensure Slow Logs feature is enabled for ElasticSearch cluster." {
    not esearch_slow_logs_is_enabled
}

esearch_slow_logs_is_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-011",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Slow Logs feature is enabled for ElasticSearch cluster.",
    "Policy Description": "It checks of slow logs is enabled for the ES cluster. Slow logs provide valuable information for optimizing and troubleshooting your search and indexing operations.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain"
}


#
# PR-AWS-CLD-ES-012
# aws::elasticsearch::domain
#

default authentication_is_saml_based  = true

authentication_is_saml_based = false {
    not input.DomainStatus.AdvancedSecurityOptions.SAMLOptions.Idp.EntityId
}

authentication_is_saml_based_err = "Ensure authentication to Kibana is SAML based in ElasticSearch." {
    not authentication_is_saml_based
}

authentication_is_saml_based_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-012",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure authentication to Kibana is SAML based in ElasticSearch.",
    "Policy Description": "It checks if basic authentication is used to login to Kibana dashboard.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain"
}


#
# PR-AWS-CLD-ES-013
# aws::elasticsearch::domain
#

default fine_grained_encryption_for_elasticsearch  = true

fine_grained_encryption_for_elasticsearch = false {
    lower(input.DomainStatus.EncryptionAtRestOptions.Enabled) == available_false_choices[_]
}

fine_grained_encryption_for_elasticsearch = false {
    lower(input.DomainStatus.DomainEndpointOptions.EnforceHTTPS) == available_false_choices[_]
}

fine_grained_encryption_for_elasticsearch = false {
    lower(input.DomainStatus.NodeToNodeEncryptionOptions.Enabled) == available_false_choices[_]
}

fine_grained_encryption_for_elasticsearch_err = "Ensure fine-grained access control is enabled during domain creation in ElasticSearch." {
    not fine_grained_encryption_for_elasticsearch
}

fine_grained_encryption_for_elasticsearch_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-013",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure fine-grained access control is enabled during domain creation in ElasticSearch.",
    "Policy Description": "It checks if fine grained access controls is enabled for the ElasticSearch cluster and node to node encryption is enabled with it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain"
}


#
# PR-AWS-CLD-ES-014
# aws::elasticsearch::domain
#

default custom_endpoint_has_certificate  = true

custom_endpoint_has_certificate = false {
    lower(input.DomainStatus.DomainEndpointOptions.CustomEndpointEnabled) == available_false_choices[_]
}

custom_endpoint_has_certificate_err = "Ensure custom endpoint has GS-managed ACM certificate associated in ElasticSearch." {
    not custom_endpoint_has_certificate
}

custom_endpoint_has_certificate_metadata := {
    "Policy Code": "PR-AWS-CLD-ES-014",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure custom endpoint has GS-managed ACM certificate associated in ElasticSearch.",
    "Policy Description": "It checks the custom endpoint is hooked to a SSL certificate from AWS ACM.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/es.html#ElasticsearchService.Client.describe_elasticsearch_domain"
}