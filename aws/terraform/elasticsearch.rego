package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html

#
# Id: 74
#

default esearch_vpc = null

aws_attribute_absence["esearch_vpc"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    not resource.properties.vpc_options
}

aws_issue["esearch_vpc"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    count([ c | resource.properties.vpc_options[_].subnet_ids != ""; c = 1]) == 0
}

esearch_vpc {
    lower(input.json.resources[_].type) == "aws_elasticsearch_domain"
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

esearch_vpc_miss_err = "Elasticsearch attribute vpc_options.subnet_ids missing in the resource" {
    aws_attribute_absence["esearch_vpc"]
}

#
# Id: 76
#

default esearch_encrypt = null

aws_issue["esearch_encrypt"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    not resource.properties.encrypt_at_rest.enabled
}

esearch_encrypt {
    lower(input.json.resources[_].type) == "aws_elasticsearch_domain"
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
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    not resource.properties.cluster_config.dedicated_master_enabled
}

esearch_master {
    lower(input.json.resources[_].type) == "aws_elasticsearch_domain"
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
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    not resource.properties.log_publishing_options
}

aws_issue["esearch_index_slow_log"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    logs := resource.properties.log_publishing_options[_]
    logs.log_type == "INDEX_SLOW_LOGS"
    logs.enabled == false
}

aws_issue["esearch_index_slow_log"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    count([ c | resource.properties.log_publishing_options[_].log_type == "INDEX_SLOW_LOGS"; c = 1]) == 0
}

esearch_index_slow_log {
    lower(input.json.resources[_].type) == "aws_elasticsearch_domain"
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

esearch_index_slow_log_miss_err = "Elasticsearch attribute log_publishing_options missing in the resource" {
    aws_attribute_absence["esearch_index_slow_log"]
}

#
# Id: 79
#

default esearch_search_slow_log = null

aws_attribute_absence["esearch_search_slow_log"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    not resource.properties.log_publishing_options
}

aws_issue["esearch_search_slow_log"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    logs := resource.properties.log_publishing_options[_]
    logs.log_type == "SEARCH_SLOW_LOGS"
    logs.enabled == false
}

aws_issue["esearch_search_slow_log"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    count([ c | resource.properties.log_publishing_options[_].log_type == "SEARCH_SLOW_LOGS"; c = 1]) == 0
}

esearch_search_slow_log {
    lower(input.json.resources[_].type) == "aws_elasticsearch_domain"
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

esearch_search_slow_log_miss_err = "Elasticsearch attribute log_publishing_options missing in the resource" {
    aws_attribute_absence["esearch_search_slow_log"]
}

#
# Id: 80
#

default esearch_zone_awareness = null

aws_issue["esearch_zone_awareness"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elasticsearch_domain"
    not resource.properties.cluster_config.zone_awareness_enabled
}

esearch_zone_awareness {
    lower(input.json.resources[_].type) == "aws_elasticsearch_domain"
    not aws_issue["esearch_zone_awareness"]
}

esearch_zone_awareness = false {
    aws_issue["esearch_zone_awareness"]
}

esearch_zone_awareness_err = "AWS Elasticsearch domain has Zone Awareness set to disabled" {
    aws_issue["esearch_zone_awareness"]
}
