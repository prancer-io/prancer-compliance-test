package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html

#
# Id: 15
#

default cf_default_cache = null

aws_attribute_absence["cf_default_cache"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.default_cache_behavior.field_level_encryption_id
}

aws_issue["cf_default_cache"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.default_cache_behavior.field_level_encryption_id) == 0
}

cf_default_cache {
    lower(input.json.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_default_cache"]
    not aws_attribute_absence["cf_default_cache"]
}

cf_default_cache = false {
    aws_issue["cf_default_cache"]
}

cf_default_cache = false {
    aws_attribute_absence["cf_default_cache"]
}

cf_default_cache_err = "AWS CloudFront Distributions with Field-Level Encryption not enabled" {
    aws_issue["cf_default_cache"]
}

cf_default_cache_miss_err = "Cloudfront attribute DistributionConfig missing in the resource" {
    aws_attribute_absence["cf_default_cache"]
}


#
# Id: 16
#

default cf_ssl_protocol = null

aws_attribute_absence["cf_ssl_protocol"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.origin.custom_origin_config.origin_ssl_protocols
}

aws_issue["cf_ssl_protocol"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.origin.custom_origin_config.origin_ssl_protocols[_]) == "sslv3"
}

cf_ssl_protocol {
    lower(input.json.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_ssl_protocol"]
    not aws_attribute_absence["cf_ssl_protocol"]
}

cf_ssl_protocol = false {
    aws_issue["cf_ssl_protocol"]
}

cf_ssl_protocol = false {
    aws_attribute_absence["cf_ssl_protocol"]
}

cf_ssl_protocol_err = "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication" {
    aws_issue["cf_ssl_protocol"]
}

cf_ssl_protocol_miss_err = "Cloudfront attribute origin_ssl_protocols missing in the resource" {
    aws_attribute_absence["cf_ssl_protocol"]
}


#
# Id: 17
#

default cf_logging = null

aws_attribute_absence["cf_logging"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.logging_config.bucket
}

aws_issue["cf_logging"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.logging_config.bucket) == 0
}

cf_logging {
    lower(input.json.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_logging"]
    not aws_attribute_absence["cf_logging"]
}

cf_logging = false {
    aws_issue["cf_logging"]
}

cf_logging = false {
    aws_attribute_absence["cf_logging"]
}

cf_logging_err = "AWS CloudFront distribution with access logging disabled" {
    aws_issue["cf_logging"]
}

cf_logging_miss_err = "Cloudfront attribute logging_config.bucket in the resource" {
    aws_attribute_absence["cf_logging"]
}

#
# Id: 18
#

default cf_https_only = null

aws_attribute_absence["cf_https_only"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.default_cache_behavior.viewer_protocol_policy
}

aws_issue["cf_https_only"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.default_cache_behavior.viewer_protocol_policy) != "https-only"
}

cf_https_only {
    lower(input.json.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_https_only"]
    not aws_attribute_absence["cf_https_only"]
}

cf_https_only = false {
    aws_issue["cf_https_only"]
}

cf_https_only = false {
    aws_attribute_absence["cf_https_only"]
}

cf_https_only_err = "AWS CloudFront origin protocol policy does not enforce HTTPS-only" {
    aws_issue["cf_https_only"]
}

cf_https_only_miss_err = "Cloudfront attribute viewer_protocol_policy missing in the resource" {
    aws_attribute_absence["cf_https_only"]
}


#
# Id: 19
#

default cf_https = null

aws_attribute_absence["cf_https"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.default_cache_behavior.viewer_protocol_policy
}

aws_issue["cf_https"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    cache := resource.properties.default_cache_behavior
    lower(cache.viewer_protocol_policy) != "https-only"
    lower(cache.viewer_protocol_policy) != "redirect-to-https"
}

cf_https {
    lower(input.json.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_https"]
    not aws_attribute_absence["cf_https"]
}

cf_https = false {
    aws_issue["cf_https"]
}

cf_https = false {
    aws_attribute_absence["cf_https"]
}

cf_https_err = "AWS CloudFront viewer protocol policy is not configured with HTTPS" {
    aws_issue["cf_https"]
}

cf_https_miss_err = "Cloudfront attribute viewer_protocol_policy missing in the resource" {
    aws_attribute_absence["cf_https"]
}

#
# Id: 20
#

default cf_min_protocol = null

aws_attribute_absence["cf_min_protocol"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.viewer_certificate.minimum_protocol_version
}

aws_issue["cf_min_protocol"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.viewer_certificate.minimum_protocol_version) == "tlsv1"
}

aws_issue["cf_min_protocol"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.viewer_certificate.minimum_protocol_version) == "tlsv1_2016"
}

cf_min_protocol {
    lower(input.json.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_min_protocol"]
    not aws_attribute_absence["cf_min_protocol"]
}

cf_min_protocol = false {
    aws_issue["cf_min_protocol"]
}

cf_min_protocol = false {
    aws_attribute_absence["cf_min_protocol"]
}

cf_min_protocol_err = "AWS CloudFront web distribution that allow TLS versions 1.0 or lower" {
    aws_issue["cf_min_protocol"]
}

cf_min_protocol_miss_err = "Cloudfront attribute minimum_protocol_version missing in the resource" {
    aws_attribute_absence["cf_min_protocol"]
}

#
# Id: 21
#

default cf_firewall = null

aws_attribute_absence["cf_firewall"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.web_acl_id
}

aws_issue["cf_firewall"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.web_acl_id) == 0
}

cf_firewall {
    lower(input.json.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_firewall"]
    not aws_attribute_absence["cf_firewall"]
}

cf_firewall = false {
    aws_issue["cf_firewall"]
}

cf_firewall = false {
    aws_attribute_absence["cf_firewall"]
}

cf_firewall_err = "AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled" {
    aws_issue["cf_firewall"]
}

cf_firewall_miss_err = "Cloudfront attribute web_acl_id missing in the resource" {
    aws_attribute_absence["cf_firewall"]
}

#
# Id: 22
#

default cf_default_ssl = null

aws_issue["cf_default_ssl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    resource.properties.viewer_certificate.cloudfront_default_certificate
}

cf_default_ssl {
    lower(input.json.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_default_ssl"]
}

cf_default_ssl = false {
    aws_issue["cf_default_ssl"]
}

cf_default_ssl_err = "AWS CloudFront web distribution with default SSL certificate (deprecated)" {
    aws_issue["cf_default_ssl"]
}

#
# Id: 23
#

default cf_geo_restriction = null

aws_attribute_absence["cf_geo_restriction"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.restrictions.geo_restriction.restriction_type
}

aws_issue["cf_geo_restriction"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.restrictions.geo_restriction.restriction_type) == "none"
}

cf_geo_restriction {
    lower(input.json.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_geo_restriction"]
    not aws_attribute_absence["cf_geo_restriction"]
}

cf_geo_restriction = false {
    aws_issue["cf_geo_restriction"]
}

cf_geo_restriction = false {
    aws_attribute_absence["cf_geo_restriction"]
}

cf_geo_restriction_err = "AWS CloudFront web distribution with geo restriction disabled" {
    aws_issue["cf_geo_restriction"]
}

cf_geo_restriction_miss_err = "Cloudfront attribute geo restriction_type missing in the resource" {
    aws_attribute_absence["cf_geo_restriction"]
}

#
# Id: 30
#

default cf_s3_origin = null

aws_attribute_absence["cf_s3_origin"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.origin
}

aws_issue["cf_s3_origin"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.origin.s3_origin_config.origin_access_identity) == 0
}

cf_s3_origin {
    lower(input.json.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_s3_origin"]
    not aws_attribute_absence["cf_s3_origin"]
}

cf_s3_origin = false {
    aws_issue["cf_s3_origin"]
}

cf_s3_origin = false {
    aws_attribute_absence["cf_s3_origin"]
}

cf_s3_origin_err = "AWS Cloudfront Distribution with S3 have Origin Access set to disabled" {
    aws_issue["cf_s3_origin"]
}

cf_s3_origin_miss_err = "Cloudfront attribute origin_access_identity missing in the resource" {
    aws_attribute_absence["cf_s3_origin"]
}
