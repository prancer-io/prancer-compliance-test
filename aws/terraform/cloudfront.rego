package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html

#
# PR-AWS-0015-TRF
#

default cf_default_cache = null

aws_issue["cf_default_cache"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.default_cache_behavior.field_level_encryption_id
}

aws_issue["cf_default_cache"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.default_cache_behavior.field_level_encryption_id) == 0
}

cf_default_cache {
    lower(input.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_default_cache"]
}

cf_default_cache = false {
    aws_issue["cf_default_cache"]
}

cf_default_cache_err = "AWS CloudFront Distributions with Field-Level Encryption not enabled" {
    aws_issue["cf_default_cache"]
}

cf_default_cache_metadata := {
    "Policy Code": "PR-AWS-0015-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFront Distributions with Field-Level Encryption not enabled",
    "Policy Description": "This policy identifies CloudFront distributions for which field-level encryption is not enabled. Field-level encryption adds an additional layer of security along with HTTPS which protects specific data throughout system processing so that only certain applications can see it.",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}


#
# PR-AWS-0016-TRF
#

default cf_ssl_protocol = null


aws_issue["cf_ssl_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.viewer_certificate.minimum_protocol_version) == "sslv3"
}

aws_issue["cf_ssl_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.origin.custom_origin_config.origin_ssl_protocols[_]) == "sslv3"
}

cf_ssl_protocol {
    lower(input.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_ssl_protocol"]
}

cf_ssl_protocol = false {
    aws_issue["cf_ssl_protocol"]
}

cf_ssl_protocol_err = "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication" {
    aws_issue["cf_ssl_protocol"]
}

cf_ssl_protocol_metadata := {
    "Policy Code": "PR-AWS-0016-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication",
    "Policy Description": "CloudFront, a content delivery network (CDN) offered by AWS, is not using a secure cipher for distribution. It is a best security practice to enforce the use of secure ciphers TLSv1.0, TLSv1.1, and/or TLSv1.2 in a CloudFront Distribution's certificate configuration. This policy scans for any deviations from this practice and returns the results.",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}


#
# PR-AWS-0017-TRF
#

default cf_logging = null

aws_attribute_absence["cf_logging"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.logging_config.bucket
}

aws_issue["cf_logging"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.logging_config.bucket) == 0
}

cf_logging {
    lower(input.resources[_].type) == "aws_cloudfront_distribution"
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

cf_logging_metadata := {
    "Policy Code": "PR-AWS-0017-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFront distribution with access logging disabled",
    "Policy Description": "This policy identifies CloudFront distributions which have access logging disabled. Enabling access log on distributions creates log files that contain detailed information about every user request that CloudFront receives. Access logs are available for web distributions. If you enable logging, you can also specify the Amazon S3 bucket that you want CloudFront to save files in.",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0018-TRF
#

default cf_https_only = null

aws_issue["cf_https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    resource.properties.origin
    not resource.properties.origin.s3_origin_config
    not resource.properties.origin.custom_origin_config
}

aws_issue["cf_https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.origin.custom_origin_config.origin_protocol_policy) != "https-only"
}

cf_https_only {
    lower(input.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_https_only"]
}

cf_https_only = false {
    aws_issue["cf_https_only"]
}

cf_https_only_err = "AWS CloudFront origin protocol policy does not enforce HTTPS-only" {
    aws_issue["cf_https_only"]
}

cf_https_only_metadata := {
    "Policy Code": "PR-AWS-0018-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFront origin protocol policy does not enforce HTTPS-only",
    "Policy Description": "It is a best security practice to enforce HTTPS-only traffic between a CloudFront distribution and the origin. This policy scans for any deviations from this practice and returns the results.",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}


#
# PR-AWS-0019-TRF
#

default cf_https = null

aws_issue["cf_https"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    cache := resource.properties.default_cache_behavior
    lower(cache.viewer_protocol_policy) != "https-only"
    lower(cache.viewer_protocol_policy) != "redirect-to-https"
}

cf_https {
    lower(input.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_https"]
}

cf_https = false {
    aws_issue["cf_https"]
}

cf_https_err = "AWS CloudFront viewer protocol policy is not configured with HTTPS" {
    aws_issue["cf_https"]
}

cf_https_metadata := {
    "Policy Code": "PR-AWS-0019-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFront viewer protocol policy is not configured with HTTPS",
    "Policy Description": "For web distributions, you can configure CloudFront to require that viewers use HTTPS to request your objects, so connections are encrypted when CloudFront communicates with viewers.",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0020-TRF
#

default cf_min_protocol = null

aws_attribute_absence["cf_min_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.viewer_certificate.minimum_protocol_version
}

aws_issue["cf_min_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.viewer_certificate.minimum_protocol_version) == "tlsv1"
}

aws_issue["cf_min_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.viewer_certificate.minimum_protocol_version) == "tlsv1_2016"
}

cf_min_protocol {
    lower(input.resources[_].type) == "aws_cloudfront_distribution"
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

cf_min_protocol_metadata := {
    "Policy Code": "PR-AWS-0020-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFront web distribution that allow TLS versions 1.0 or lower",
    "Policy Description": "This policy identifies AWS CloudFront web distributions which are configured with TLS versions for HTTPS communication between viewers and CloudFront. As a best practice, use TLSv1.1_2016 or later as the minimum protocol version in your CloudFront distribution security policies.",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0021-TRF
#

default cf_firewall = null

aws_attribute_absence["cf_firewall"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.web_acl_id
}

aws_issue["cf_firewall"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.web_acl_id) == 0
}

cf_firewall {
    lower(input.resources[_].type) == "aws_cloudfront_distribution"
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

cf_firewall_metadata := {
    "Policy Code": "PR-AWS-0021-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled",
    "Policy Description": "This policy identifies Amazon CloudFront web distributions which have the AWS Web Application Firewall (AWS WAF) service disabled. As a best practice, enable the AWS WAF service on CloudFront web distributions to protect against application layer attacks. To block malicious requests to your Cloudfront Content Delivery Network, define the block criteria in the WAF web access control list (web ACL).",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0022-TRF
#

default cf_default_ssl = null

aws_issue["cf_default_ssl"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    resource.properties.viewer_certificate.cloudfront_default_certificate
}

cf_default_ssl {
    lower(input.resources[_].type) == "aws_cloudfront_distribution"
    not aws_issue["cf_default_ssl"]
}

cf_default_ssl = false {
    aws_issue["cf_default_ssl"]
}

cf_default_ssl_err = "AWS CloudFront web distribution with default SSL certificate (deprecated)" {
    aws_issue["cf_default_ssl"]
}

cf_default_ssl_metadata := {
    "Policy Code": "PR-AWS-0022-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFront web distribution with default SSL certificate",
    "Policy Description": "This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0023-TRF
#

default cf_geo_restriction = null

aws_attribute_absence["cf_geo_restriction"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.restrictions.geo_restriction.restriction_type
}

aws_issue["cf_geo_restriction"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    lower(resource.properties.restrictions.geo_restriction.restriction_type) == "none"
}

cf_geo_restriction {
    lower(input.resources[_].type) == "aws_cloudfront_distribution"
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

cf_geo_restriction_metadata := {
    "Policy Code": "PR-AWS-0023-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS CloudFront web distribution with geo restriction disabled",
    "Policy Description": "This policy identifies CloudFront web distributions which have geo restriction feature disabled. Geo Restriction has the ability to block IP addresses based on Geo IP by whitelist or blacklist a country in order to allow or restrict users in specific locations from accessing web application content.",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0030-TRF
#

default cf_s3_origin = null

aws_attribute_absence["cf_s3_origin"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.origin
}

aws_issue["cf_s3_origin"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.origin.s3_origin_config.origin_access_identity) == 0
}

cf_s3_origin {
    lower(input.resources[_].type) == "aws_cloudfront_distribution"
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

cf_s3_origin_metadata := {
    "Policy Code": "PR-AWS-0030-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Cloudfront Distribution with S3 have Origin Access set to disabled",
    "Policy Description": "This policy identifies the AWS CloudFront distributions which are utilizing S3 bucket and have Origin Access Disabled. The origin access identity feature should be enabled for all your AWS CloudFront CDN distributions in order to restrict any direct access to your objects through Amazon S3 URLs.",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}
