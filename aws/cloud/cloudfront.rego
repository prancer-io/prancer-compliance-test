package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html

#
# PR-AWS-CLD-CF-001
#

default cf_default_cache = true

cf_default_cache = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    not input.Distribution.DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId
}

cf_default_cache = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    count(input.Distribution.DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId) == 0
}

cf_default_cache_err = "AWS CloudFront Distributions with Field-Level Encryption not enabled" {
    not cf_default_cache
}

cf_default_cache_metadata := {
    "Policy Code": "PR-AWS-CLD-CF-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudFront Distributions with Field-Level Encryption not enabled",
    "Policy Description": "This policy identifies CloudFront distributions for which field-level encryption is not enabled. Field-level encryption adds an additional layer of security along with HTTPS which protects specific data throughout system processing so that only certain applications can see it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}


#
# PR-AWS-CLD-CF-002
#

default cf_ssl_protocol = true

cf_ssl_protocol = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    cert := input.Distribution.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "sslv3"
}

cf_ssl_protocol = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    origin_items := input.Distribution.DistributionConfig.Origins.Items[j]
    lower(origin_items.CustomOriginConfig.OriginSslProtocols.Items[k]) == "sslv3"
}

cf_ssl_protocol_err = "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication" {
    not cf_ssl_protocol
}

cf_ssl_protocol_metadata := {
    "Policy Code": "PR-AWS-CLD-CF-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication",
    "Policy Description": "CloudFront, a content delivery network (CDN) offered by AWS, is not using a secure cipher for distribution. It is a best security practice to enforce the use of secure ciphers TLSv1.0, TLSv1.1, and/or TLSv1.2 in a CloudFront Distribution's certificate configuration. This policy scans for any deviations from this practice and returns the results.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}


#
# PR-AWS-CLD-CF-003
#

default cf_logging = true

cf_logging = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    not input.Distribution.DistributionConfig.Logging.Bucket
}

cf_logging = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    count(input.Distribution.DistributionConfig.Logging.Bucket) == 0
}

cf_logging_err = "AWS CloudFront distribution with access logging disabled" {
    not cf_logging
}

cf_logging_metadata := {
    "Policy Code": "PR-AWS-CLD-CF-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudFront distribution with access logging disabled",
    "Policy Description": "This policy identifies CloudFront distributions which have access logging disabled. Enabling access log on distributions creates log files that contain detailed information about every user request that CloudFront receives. Access logs are available for web distributions. If you enable logging, you can also specify the Amazon S3 bucket that you want CloudFront to save files in.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-CLD-CF-004
#

default cf_https_only = true

cf_https_only = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    count(
        [c | lower(input.Distribution.DistributionConfig.Origins.Items[_].CustomOriginConfig.OriginProtocolPolicy) != "https-only"; c := 1
    ]) > 0
}

cf_https_only_err = "AWS CloudFront origin protocol policy does not enforce HTTPS-only" {
    not cf_https_only
}

cf_https_only_metadata := {
    "Policy Code": "PR-AWS-CLD-CF-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudFront origin protocol policy does not enforce HTTPS-only",
    "Policy Description": "It is a best security practice to enforce HTTPS-only traffic between a CloudFront distribution and the origin. This policy scans for any deviations from this practice and returns the results.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}


#
# PR-AWS-CLD-CF-005
#

default cf_https = true

cf_https = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    not input.Distribution.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy
}

cf_https = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    cache := input.Distribution.DistributionConfig.DefaultCacheBehavior
    lower(cache.ViewerProtocolPolicy) != "https-only"
    lower(cache.ViewerProtocolPolicy) != "redirect-to-https"
}

cf_https_err = "AWS CloudFront viewer protocol policy is not configured with HTTPS" {
    not cf_https
}

cf_https_metadata := {
    "Policy Code": "PR-AWS-CLD-CF-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudFront viewer protocol policy is not configured with HTTPS",
    "Policy Description": "For web distributions, you can configure CloudFront to require that viewers use HTTPS to request your objects, so connections are encrypted when CloudFront communicates with viewers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-CLD-CF-006
#

default cf_min_protocol = true

cf_min_protocol = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    cert := input.Distribution.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1"
}

cf_min_protocol = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    cert := input.Distribution.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1_2016"
}

cf_min_protocol_err = "AWS CloudFront web distribution that allow TLS versions 1.0 or lower" {
    not cf_min_protocol
}

cf_min_protocol_metadata := {
    "Policy Code": "PR-AWS-CLD-CF-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudFront web distribution that allow TLS versions 1.0 or lower",
    "Policy Description": "This policy identifies AWS CloudFront web distributions which are configured with TLS versions for HTTPS communication between viewers and CloudFront. As a best practice, use TLSv1.1_2016 or later as the minimum protocol version in your CloudFront distribution security policies.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-CLD-CF-007
#

default cf_firewall = true

cf_firewall = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    not input.Distribution.DistributionConfig.WebACLId
}

cf_firewall = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    count(input.Distribution.DistributionConfig.WebACLId) == 0
}

cf_firewall_err = "AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled" {
    not cf_firewall
}

cf_firewall_metadata := {
    "Policy Code": "PR-AWS-CLD-CF-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled",
    "Policy Description": "This policy identifies Amazon CloudFront web distributions which have the AWS Web Application Firewall (AWS WAF) service disabled. As a best practice, enable the AWS WAF service on CloudFront web distributions to protect against application layer attacks. To block malicious requests to your Cloudfront Content Delivery Network, define the block criteria in the WAF web access control list (web ACL).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-CLD-CF-008
#

default cf_default_ssl = true

cf_default_ssl = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    input.Distribution.DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate == true
}

cf_default_ssl_err = "AWS CloudFront web distribution with default SSL certificate (deprecated)" {
    not cf_default_ssl
}

cf_default_ssl_metadata := {
    "Policy Code": "PR-AWS-CLD-CF-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudFront web distribution with default SSL certificate",
    "Policy Description": "This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-CLD-CF-009
#

default cf_geo_restriction = true

cf_geo_restriction = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    not input.Distribution.DistributionConfig.Restrictions
}


cf_geo_restriction = false {
    # lower(resource.Type) == "aws::cloudfront::distribution"
    lower(input.Distribution.DistributionConfig.Restrictions.GeoRestriction.RestrictionType) == "none"
}

cf_geo_restriction_err = "AWS CloudFront web distribution with geo restriction disabled" {
    not cf_geo_restriction
}

cf_geo_restriction_metadata := {
    "Policy Code": "PR-AWS-CLD-CF-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS CloudFront web distribution with geo restriction disabled",
    "Policy Description": "This policy identifies CloudFront web distributions which have geo restriction feature disabled. Geo Restriction has the ability to block IP addresses based on Geo IP by whitelist or blacklist a country in order to allow or restrict users in specific locations from accessing web application content.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}
