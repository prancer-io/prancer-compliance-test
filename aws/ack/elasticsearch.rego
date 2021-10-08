package rule

# https://github.com/aws-controllers-k8s/elasticsearchservice-controller

#
# PR-AWS-0074-ACK
#

default esearch_vpc = null

aws_issue["esearch_vpc"] {
    lower(input.kind) == "elasticsearchdomain"
    not input.spec.vpcOptions.subnetIDs
}

aws_issue["esearch_vpc"] {
    lower(input.kind) == "elasticsearchdomain"
    count(input.spec.vpcOptions.subnetIDs) == 0
}

esearch_vpc {
    lower(input.kind) == "elasticsearchdomain"
    not aws_issue["esearch_vpc"]
}

esearch_vpc = false {
    aws_issue["esearch_vpc"]
}

esearch_vpc_err = "AWS ElasticSearch cluster not in a VPC" {
    aws_issue["esearch_vpc"]
}

esearch_vpc_metadata := {
    "Policy Code": "PR-AWS-0074-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS ElasticSearch cluster not in a VPC",
    "Policy Description": "VPC support for Amazon ES is easy to configure, reliable, and offers an extra layer of security. With VPC support, traffic between other services and Amazon ES stays entirely within the AWS network, isolated from the public Internet. You can manage network access using existing VPC security groups, and you can use AWS Identity and Access Management (IAM) policies for additional protection. VPC support for Amazon ES domains is available at no additional charge.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-0076-ACK
#

default esearch_encrypt = null

aws_issue["esearch_encrypt"] {
    lower(input.kind) == "elasticsearchdomain"
    not input.spec.encryptionAtRestOptions.enabled
}

esearch_encrypt {
    lower(input.kind) == "elasticsearchdomain"
    not aws_issue["esearch_encrypt"]
}

esearch_encrypt = false {
    aws_issue["esearch_encrypt"]
}

esearch_encrypt_err = "AWS Elasticsearch domain Encryption for data at rest is disabled" {
    aws_issue["esearch_encrypt"]
}

esearch_encrypt_metadata := {
    "Policy Code": "PR-AWS-0076-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS Elasticsearch domain Encryption for data at rest is disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which encryption is disabled. Encryption of data at rest is required to prevent unauthorized users from accessing the sensitive information available on your Elasticsearch domains components. This may include all data of file systems, primary and replica indices, log files, memory swap files and automated snapshots. The Elasticsearch uses AWS KMS service to store and manage the encryption keys. It is highly recommended to implement encryption at rest when you are working with production data that have sensitive information, to protect from unauthorized access.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-0077-ACK
#

default esearch_master = null

aws_issue["esearch_master"] {
    lower(input.kind) == "elasticsearchdomain"
    not input.spec.elasticsearchClusterConfig.dedicatedMasterEnabled
}

esearch_master {
    lower(input.kind) == "elasticsearchdomain"
    not aws_issue["esearch_master"]
}

esearch_master = false {
    aws_issue["esearch_master"]
}

esearch_master_err = "AWS Elasticsearch domain has Dedicated master set to disabled" {
    aws_issue["esearch_master"]
}

esearch_master_metadata := {
    "Policy Code": "PR-AWS-0077-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS Elasticsearch domain has Dedicated master set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Dedicated master is disabled in your AWS account. If dedicated master nodes are provided those handle the management tasks and cluster nodes can easily manage index and search requests from different types of workload and make them more resilient in production. Dedicated master nodes improve environmental stability by freeing all the management tasks from the cluster data nodes.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}

#
# PR-AWS-0080-ACK
#

default esearch_zone_awareness = null

aws_issue["esearch_zone_awareness"] {
    lower(input.kind) == "elasticsearchdomain"
    not input.spec.elasticsearchClusterConfig.zoneAwarenessEnabled
}

esearch_zone_awareness {
    lower(input.kind) == "elasticsearchdomain"
    not aws_issue["esearch_zone_awareness"]
}

esearch_zone_awareness = false {
    aws_issue["esearch_zone_awareness"]
}

esearch_zone_awareness_err = "AWS Elasticsearch domain has Zone Awareness set to disabled" {
    aws_issue["esearch_zone_awareness"]
}

esearch_zone_awareness_metadata := {
    "Policy Code": "PR-AWS-0080-ACK",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "ACK",
    "Policy Title": "AWS Elasticsearch domain has Zone Awareness set to disabled",
    "Policy Description": "This policy identifies Elasticsearch domains for which Zone Awareness is disabled in your AWS account. Enabling Zone Awareness (cross-zone replication) increases the availability by distributing your Elasticsearch data nodes across two availability zones available in the same AWS region. It also prevents data loss and minimizes downtime in the event of node or availability zone failure.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html"
}
