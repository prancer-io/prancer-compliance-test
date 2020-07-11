package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html

#
# Id: 15
#

default cf_default_cache = null

cf_default_cache {
    lower(input.Type) == "aws::cloudfront::distribution"
    count(input.Properties.DistributionConfig.DefaultCacheBehavior) > 0
}

cf_default_cache = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    count(input.Properties.DistributionConfig.DefaultCacheBehavior) == 0
}

cf_default_cache = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    not input.Properties.DistributionConfig.DefaultCacheBehavior
}

cf_default_cache_err = "AWS CloudFront Distributions with Field-Level Encryption not enabled" {
    cf_default_cache == false
}

#
# Id: 16
#

default cf_ssl_protocol = null

cf_ssl_protocol {
    lower(input.Type) == "aws::cloudfront::distribution"
    count(
        [c | lower(input.Properties.DistributionConfig.Origins[_].CustomOriginConfig.OriginSSLProtocols[_]) == "sslv3"; c := 1
    ]) == 0
}

cf_ssl_protocol = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    origins := input.Properties.DistributionConfig.Origins[_]
    lower(origins.CustomOriginConfig.OriginSSLProtocols[_]) == "sslv3"
}

cf_ssl_protocol_err = "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication" {
    cf_ssl_protocol == false
}

#
# Id: 17
#

default cf_logging = null

cf_logging {
    lower(input.Type) == "aws::cloudfront::distribution"
    count(input.Properties.DistributionConfig.Logging.Bucket) > 0
}

cf_logging = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    count(input.Properties.DistributionConfig.Logging.Bucket) == 0
}

cf_logging = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    not input.Properties.DistributionConfig.Logging.Bucket
}

cf_logging_err = "AWS CloudFront distribution with access logging disabled" {
    cf_logging == false
}

#
# Id: 18
#

default cf_https_only = null

cf_https_only {
    lower(input.Type) == "aws::cloudfront::distribution"
    count(
        [c | lower(input.Properties.DistributionConfig.Origins[_].CustomOriginConfig.OriginProtocolPolicy) != "https-only"; c := 1
    ]) == 0
}

cf_https_only = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    count(
        [c | lower(input.Properties.DistributionConfig.Origins[_].CustomOriginConfig.OriginProtocolPolicy) != "https-only"; c := 1
    ]) > 0
}

cf_https_only_err = "AWS CloudFront origin protocol policy does not enforce HTTPS-only" {
    cf_https_only == false
}

#
# Id: 19
#

default cf_https = null

cf_https {
    lower(input.Type) == "aws::cloudfront::distribution"
    cache := input.Properties.DistributionConfig.DefaultCacheBehavior
    lower(cache.ViewerProtocolPolicy) == "https-only"
}

cf_https {
    lower(input.Type) == "aws::cloudfront::distribution"
    cache := input.Properties.DistributionConfig.DefaultCacheBehavior
    lower(cache.ViewerProtocolPolicy) == "redirect-to-https"
}

cf_https = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    not input.Properties.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy
}

cf_https = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    cache := input.Properties.DistributionConfig.DefaultCacheBehavior
    lower(cache.ViewerProtocolPolicy) != "https-only"
    lower(cache.ViewerProtocolPolicy) != "redirect-to-https"
}

cf_https_err = "AWS CloudFront viewer protocol policy is not configured with HTTPS" {
    cf_https == false
}

#
# Id: 20
#

default cf_min_protocol = null

cf_min_protocol {
    lower(input.Type) == "aws::cloudfront::distribution"
    cert := input.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) != "tlsv1"
    lower(cert.MinimumProtocolVersion) != "tlsv1_2016"
}

cf_min_protocol = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    cert := input.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1"
}

cf_min_protocol = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    cert := input.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1_2016"
}

cf_min_protocol_err = "AWS CloudFront web distribution that allow TLS versions 1.0 or lower" {
    cf_min_protocol == false
}

#
# Id: 21
#

default cf_firewall = null

cf_firewall {
    lower(input.Type) == "aws::cloudfront::distribution"
    count(input.Properties.DistributionConfig.WebACLId) > 0
}

cf_firewall = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    count(input.Properties.DistributionConfig.WebACLId) == 0
}

cf_firewall = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    not input.Properties.DistributionConfig.WebACLId
}

cf_firewall_err = "AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled" {
    cf_firewall == false
}

#
# Id: 22
#

default cf_default_ssl = null

cf_default_ssl {
    lower(input.Type) == "aws::cloudfront::distribution"
    not input.Properties.DistributionConfig.viewerCertificate.certificateSource
}

cf_default_ssl = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    input.Properties.DistributionConfig.viewerCertificate.certificateSource
}

cf_default_ssl_err = "AWS CloudFront web distribution with default SSL certificate (deprecated)" {
    cf_default_ssl == false
}

#
# Id: 23
#

default cf_geo_restriction = null

cf_geo_restriction {
    lower(input.Type) == "aws::cloudfront::distribution"
    lower(input.Properties.DistributionConfig.Restrictions.GeoRestriction.RestrictionType) != "none"
}

cf_geo_restriction {
    lower(input.Type) == "aws::cloudfront::distribution"
    not input.Properties.DistributionConfig.Restrictions.GeoRestriction.RestrictionType
}

cf_geo_restriction = false {
    lower(input.Type) == "aws::cloudfront::distribution"
    lower(input.Properties.DistributionConfig.Restrictions.GeoRestriction.RestrictionType) == "none"
}

cf_geo_restriction_err = "AWS CloudFront web distribution with geo restriction disabled" {
    cf_geo_restriction == false
}

#
# Id: 24
#

default cf_s3_origin = null

cf_s3_origin {
    lower(input.Type) == "aws::cloudfront::distribution"
    count(
        [c | count(input.Properties.DistributionConfig.Origins[_].S3OriginConfig.OriginAccessIdentity) == 0; c := 1
    ]) == 0
}

cf_s3_origin = false {
     lower(input.Type) == "aws::cloudfront::distribution"
    count(
        [c | count(input.Properties.DistributionConfig.Origins[_].S3OriginConfig.OriginAccessIdentity) == 0; c := 1
    ]) > 0
}

cf_s3_origin_err = "AWS Cloudfront Distribution with S3 have Origin Access set to disabled" {
    cf_s3_origin == false
}
