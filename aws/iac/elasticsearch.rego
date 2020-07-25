package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html

#
# Id: 74
#

default esearch_vpc = null

aws_attribute_absence["esearch_vpc"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.VPCOptions.SubnetIds
}

aws_issue["esearch_vpc"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.VPCOptions.SubnetIds) == 0
}

esearch_vpc {
    lower(input.resources[_].Type) == "aws::elasticsearch::domain"
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
# Id: 76
#

default esearch_encrypt = null

aws_issue["esearch_encrypt"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.EncryptionAtRestOptions.Enabled
}

esearch_encrypt {
    lower(input.resources[_].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_encrypt"]
}

esearch_encrypt = false {
    aws_issue["esearch_encrypt"]
}

esearch_encrypt_err = "AWS Elasticsearch domain Encryption for data at rest is disabled" {
    aws_issue["esearch_encrypt"]
}

#
# Id: 77
#

default esearch_master = null

aws_issue["esearch_master"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.ElasticsearchClusterConfig.DedicatedMasterEnabled
}

esearch_master {
    lower(input.resources[_].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_master"]
}

esearch_master = false {
    aws_issue["esearch_master"]
}

esearch_master_err = "AWS Elasticsearch domain has Dedicated master set to disabled" {
    aws_issue["esearch_master"]
}

#
# Id: 78
#

default esearch_index_slow_log = null

aws_attribute_absence["esearch_index_slow_log"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions
}

aws_issue["esearch_index_slow_log"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled
}

aws_issue["esearch_index_slow_log"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn
}

aws_issue["esearch_index_slow_log"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn) == 0
}

esearch_index_slow_log {
    lower(input.resources[_].Type) == "aws::elasticsearch::domain"
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
# Id: 79
#

default esearch_search_slow_log = null

aws_attribute_absence["esearch_search_slow_log"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions
}

aws_issue["esearch_search_slow_log"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled
}

aws_issue["esearch_search_slow_log"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn
}

aws_issue["esearch_search_slow_log"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    count(resource.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn) == 0
}

esearch_search_slow_log {
    lower(input.resources[_].Type) == "aws::elasticsearch::domain"
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

esearch_search_slow_log_miss_err = "Elasticsearch attribute agentPoolProfiles missing in the resource" {
    aws_attribute_absence["esearch_search_slow_log"]
}

#
# Id: 80
#

default esearch_zone_awareness = null

aws_issue["esearch_zone_awareness"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::elasticsearch::domain"
    not resource.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled
}

esearch_zone_awareness {
    lower(input.resources[_].Type) == "aws::elasticsearch::domain"
    not aws_issue["esearch_zone_awareness"]
}

esearch_zone_awareness = false {
    aws_issue["esearch_zone_awareness"]
}

esearch_zone_awareness_err = "AWS Elasticsearch domain has Zone Awareness set to disabled" {
    aws_issue["esearch_zone_awareness"]
}
