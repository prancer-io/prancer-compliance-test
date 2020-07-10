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
# Id: 
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


config where cloud.type = 'aws' AND api.name = 'aws-cloudfront-list-distributions' AND json.rule = 'logging.enabled is false and logging.bucket is empty'



