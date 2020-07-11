package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html

#
# Id: 74
#

default esearch_vpc = null

esearch_vpc {
    lower(input.Type) == "aws::elasticsearch::domain"
    count(input.Properties.VPCOptions.SubnetIds) > 0
}

esearch_vpc = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    count(input.Properties.VPCOptions.SubnetIds) == 0
}

esearch_vpc = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.VPCOptions.SubnetIds
}

esearch_vpc_err = "AWS ElasticSearch cluster not in a VPC" {
    esearch_vpc == false
}

#
# Id: 76
#

default esearch_encrypt = null

esearch_encrypt {
    lower(input.Type) == "aws::elasticsearch::domain"
    input.Properties.EncryptionAtRestOptions.Enabled == true
}

esearch_encrypt = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    input.Properties.EncryptionAtRestOptions.Enabled == false
}

esearch_encrypt = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.EncryptionAtRestOptions.Enabled
}

esearch_encrypt_err = "AWS Elasticsearch domain Encryption for data at rest is disabled" {
    esearch_encrypt == false
}

#
# Id: 77
#

default esearch_master = null

esearch_master {
    lower(input.Type) == "aws::elasticsearch::domain"
    input.Properties.ElasticsearchClusterConfig.DedicatedMasterEnabled == true
}

esearch_master = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    input.Properties.ElasticsearchClusterConfig.DedicatedMasterEnabled == false
}

esearch_master = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.ElasticsearchClusterConfig.DedicatedMasterEnabled
}

esearch_master_err = "AWS Elasticsearch domain has Dedicated master set to disabled" {
    esearch_master == false
}

#
# Id: 78
#

default esearch_index_slow_log = null

esearch_index_slow_log {
    lower(input.Type) == "aws::elasticsearch::domain"
    input.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled == true
    startswith(lower(input.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn), "arn:")
}

esearch_index_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.LogPublishingOptions
}

esearch_index_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.LogPublishingOptions.INDEX_SLOW_LOGS
}

esearch_index_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled
}

esearch_index_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn
}

esearch_index_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    input.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.Enabled == false
}

esearch_index_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    count(input.Properties.LogPublishingOptions.INDEX_SLOW_LOGS.CloudWatchLogsLogGroupArn) == 0
}

esearch_index_slow_log_err = "AWS Elasticsearch domain has Index slow logs set to disabled" {
    esearch_index_slow_log == false
}

#
# Id: 79
#

default esearch_search_slow_log = null

esearch_search_slow_log {
    lower(input.Type) == "aws::elasticsearch::domain"
    input.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled == true
    startswith(lower(input.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn), "arn:")
}

esearch_search_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.LogPublishingOptions
}

esearch_search_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS
}

esearch_search_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled
}

esearch_search_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn
}

esearch_search_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    input.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.Enabled == false
}

esearch_search_slow_log = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    count(input.Properties.LogPublishingOptions.SEARCH_SLOW_LOGS.CloudWatchLogsLogGroupArn) == 0
}

esearch_search_slow_log_err = "AWS Elasticsearch domain has Search slow logs set to disabled" {
    esearch_search_slow_log == false
}

#
# Id: 80
#

default esearch_zone_awareness = null

esearch_zone_awareness {
    lower(input.Type) == "aws::elasticsearch::domain"
    input.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled == true
}

esearch_zone_awareness = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    input.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled == false
}

esearch_zone_awareness = false {
    lower(input.Type) == "aws::elasticsearch::domain"
    not input.Properties.ElasticsearchClusterConfig.ZoneAwarenessEnabled
}

esearch_zone_awareness_err = "AWS Elasticsearch domain has Zone Awareness set to disabled" {
    esearch_zone_awareness == false
}
