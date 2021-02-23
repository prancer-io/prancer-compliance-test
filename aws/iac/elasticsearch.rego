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

#
# PR-AWS-0076-CFR
#

default esearch_encrypt = null

aws_issue["esearch_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.EncryptionAtRestOptions.Enabled
}

esearch_encrypt {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_encrypt"]
}

esearch_encrypt = false {
    aws_issue["esearch_encrypt"]
}

esearch_encrypt_err = "AWS Elasticsearch domain Encryption for data at rest is disabled" {
    aws_issue["esearch_encrypt"]
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
    not aws_attribute_absence["esearch_index_slow_log"]
}

esearch_index_slow_log = false {
    aws_issue["esearch_index_slow_log"]
}

esearch_index_slow_log = false {
    aws_attribute_absence["esearch_index_slow_log"]
}

esearch_index_slow_log_err = "AWS Elasticsearch domain has Index slow logs set to disabled" {
    aws_issue["esearch_index_slow_log"]
}

esearch_index_slow_log_miss_err = "Elasticsearch attribute LogPublishingOptions missing in the resource" {
    aws_attribute_absence["esearch_index_slow_log"]
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
    not aws_attribute_absence["esearch_search_slow_log"]
}

esearch_search_slow_log = false {
    aws_issue["esearch_search_slow_log"]
}

esearch_search_slow_log = false {
    aws_attribute_absence["esearch_search_slow_log"]
}

esearch_search_slow_log_err = "AWS Elasticsearch domain has Search slow logs set to disabled" {
    aws_issue["esearch_search_slow_log"]
}

esearch_search_slow_log_miss_err = "Elasticsearch attribute LogPublishingOptions missing in the resource" {
    aws_attribute_absence["esearch_search_slow_log"]
}

#
# PR-AWS-0080-CFR
#

default esearch_zone_awareness = null

aws_issue["esearch_zone_awareness"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled
}

esearch_zone_awareness {
    lower(input.Resources[i].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_zone_awareness"]
}

esearch_zone_awareness = false {
    aws_issue["esearch_zone_awareness"]
}

esearch_zone_awareness_err = "AWS Elasticsearch domain has Zone Awareness set to disabled" {
    aws_issue["esearch_zone_awareness"]
}
