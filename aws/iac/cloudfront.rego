package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html

#
# Id: 15
#

default cf_default_cache = null

aws_attribute_absence["cf_default_cache"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.DefaultCacheBehavior
}

aws_issue["cf_default_cache"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.DefaultCacheBehavior) == 0
}

cf_default_cache {
    lower(input.resources[_].Type) == "aws::cloudfront::distribution"
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
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Origins
}

aws_issue["cf_ssl_protocol"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    origins := resource.Properties.DistributionConfig.Origins[_]
    lower(origins.CustomOriginConfig.OriginSSLProtocols[_]) == "sslv3"
}

cf_ssl_protocol {
    lower(input.resources[_].Type) == "aws::cloudfront::distribution"
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

cf_ssl_protocol_miss_err = "Cloudfront attribute DistributionConfig Origins missing in the resource" {
    aws_attribute_absence["cf_ssl_protocol"]
}


#
# Id: 17
#

default cf_logging = null

aws_attribute_absence["cf_logging"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Logging.Bucket
}

aws_issue["cf_logging"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.Logging.Bucket) == 0
}

cf_logging {
    lower(input.resources[_].Type) == "aws::cloudfront::distribution"
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

cf_logging_miss_err = "Cloudfront attribute DistributionConfig Logging in the resource" {
    aws_attribute_absence["cf_logging"]
}

#
# Id: 18
#

default cf_https_only = null

aws_attribute_absence["cf_https_only"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Origins
}

aws_issue["cf_https_only"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(
        [c | lower(resource.Properties.DistributionConfig.Origins[_].CustomOriginConfig.OriginProtocolPolicy) != "https-only"; c := 1
    ]) > 0
}

cf_https_only {
    lower(input.resources[_].Type) == "aws::cloudfront::distribution"
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

cf_https_only_miss_err = "Cloudfront attribute DistributionConfig Origins missing in the resource" {
    aws_attribute_absence["cf_https_only"]
}


#
# Id: 19
#

default cf_https = null

aws_attribute_absence["cf_https"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy
}

aws_issue["cf_https"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cache := resource.Properties.DistributionConfig.DefaultCacheBehavior
    lower(cache.ViewerProtocolPolicy) != "https-only"
    lower(cache.ViewerProtocolPolicy) != "redirect-to-https"
}

cf_https {
    lower(input.resources[_].Type) == "aws::cloudfront::distribution"
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

cf_https_miss_err = "Cloudfront attribute ViewerProtocolPolicy missing in the resource" {
    aws_attribute_absence["cf_https"]
}

#
# Id: 20
#

default cf_min_protocol = null

aws_attribute_absence["cf_min_protocol"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.ViewerCertificate.MinimumProtocolVersion
}

aws_issue["cf_min_protocol"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cert := resource.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1"
}

aws_issue["cf_min_protocol"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cert := resource.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1_2016"
}

cf_min_protocol {
    lower(input.resources[_].Type) == "aws::cloudfront::distribution"
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

cf_min_protocol_miss_err = "Cloudfront attribute MinimumProtocolVersion missing in the resource" {
    aws_attribute_absence["cf_min_protocol"]
}

#
# Id: 21
#

default cf_firewall = null

aws_attribute_absence["cf_firewall"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.WebACLId
}

aws_issue["cf_firewall"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.WebACLId) == 0
}

cf_firewall {
    lower(input.resources[_].Type) == "aws::cloudfront::distribution"
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

cf_firewall_miss_err = "Cloudfront attribute WebACLId missing in the resource" {
    aws_attribute_absence["cf_firewall"]
}

#
# Id: 22
#

default cf_default_ssl = null

aws_issue["cf_default_ssl"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    input.Properties.DistributionConfig.viewerCertificate.certificateSource
}

cf_default_ssl {
    lower(input.resources[_].Type) == "aws::cloudfront::distribution"
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
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Restrictions.GeoRestriction.RestrictionType
}

aws_issue["cf_geo_restriction"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    lower(resource.Properties.DistributionConfig.Restrictions.GeoRestriction.RestrictionType) == "none"
}

cf_geo_restriction {
    lower(input.resources[_].Type) == "aws::cloudfront::distribution"
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

cf_geo_restriction_miss_err = "Cloudfront attribute Geo RestrictionType missing in the resource" {
    aws_attribute_absence["cf_geo_restriction"]
}

#
# Id: 24
#

default cf_s3_origin = null

aws_attribute_absence["cf_s3_origin"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Origins
}

aws_issue["cf_s3_origin"] {
    resource := input.resources[_]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(
        [c | count(resource.Properties.DistributionConfig.Origins[_].S3OriginConfig.OriginAccessIdentity) == 0; c := 1
    ]) > 0
}

cf_s3_origin {
    lower(input.resources[_].Type) == "aws::cloudfront::distribution"
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

cf_s3_origin_miss_err = "Cloudfront attribute Origins missing in the resource" {
    aws_attribute_absence["cf_s3_origin"]
}
