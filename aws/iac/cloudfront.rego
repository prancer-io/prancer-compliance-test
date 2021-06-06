package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html

#
# PR-AWS-0015-CFR
#

default cf_default_cache = null

aws_attribute_absence["cf_default_cache"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.DefaultCacheBehavior
}

aws_issue["cf_default_cache"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.DefaultCacheBehavior) == 0
}

cf_default_cache {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
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

cf_default_cache_metadata := {
    "Policy Code": "PR-AWS-0015-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront Distributions with Field-Level Encryption not enabled",
    "Policy Description": "This policy identifies CloudFront distributions for which field-level encryption is not enabled. Field-level encryption adds an additional layer of security along with HTTPS which protects specific data throughout system processing so that only certain applications can see it.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}


#
# PR-AWS-0016-CFR
#

default cf_ssl_protocol = null

aws_attribute_absence["cf_ssl_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Origins
}

aws_issue["cf_ssl_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    origins := resource.Properties.DistributionConfig.Origins[_]
    lower(origins.CustomOriginConfig.OriginSSLProtocols[_]) == "sslv3"
}

cf_ssl_protocol {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
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

cf_ssl_protocol_metadata := {
    "Policy Code": "PR-AWS-0016-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication",
    "Policy Description": "CloudFront, a content delivery network (CDN) offered by AWS, is not using a secure cipher for distribution. It is a best security practice to enforce the use of secure ciphers TLSv1.0, TLSv1.1, and/or TLSv1.2 in a CloudFront Distribution's certificate configuration. This policy scans for any deviations from this practice and returns the results.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}


#
# PR-AWS-0017-CFR
#

default cf_logging = null

aws_attribute_absence["cf_logging"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Logging.Bucket
}

aws_issue["cf_logging"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.Logging.Bucket) == 0
}

cf_logging {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
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

cf_logging_metadata := {
    "Policy Code": "PR-AWS-0017-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront distribution with access logging disabled",
    "Policy Description": "This policy identifies CloudFront distributions which have access logging disabled. Enabling access log on distributions creates log files that contain detailed information about every user request that CloudFront receives. Access logs are available for web distributions. If you enable logging, you can also specify the Amazon S3 bucket that you want CloudFront to save files in.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0018-CFR
#

default cf_https_only = null

aws_attribute_absence["cf_https_only"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Origins
}

aws_issue["cf_https_only"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(
        [c | lower(resource.Properties.DistributionConfig.Origins[_].CustomOriginConfig.OriginProtocolPolicy) != "https-only"; c := 1
    ]) > 0
}

cf_https_only {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
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

cf_https_only_metadata := {
    "Policy Code": "PR-AWS-0018-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront origin protocol policy does not enforce HTTPS-only",
    "Policy Description": "It is a best security practice to enforce HTTPS-only traffic between a CloudFront distribution and the origin. This policy scans for any deviations from this practice and returns the results.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}


#
# PR-AWS-0019-CFR
#

default cf_https = null

aws_attribute_absence["cf_https"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy
}

aws_issue["cf_https"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cache := resource.Properties.DistributionConfig.DefaultCacheBehavior
    lower(cache.ViewerProtocolPolicy) != "https-only"
    lower(cache.ViewerProtocolPolicy) != "redirect-to-https"
}

cf_https {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
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

cf_https_metadata := {
    "Policy Code": "PR-AWS-0019-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront viewer protocol policy is not configured with HTTPS",
    "Policy Description": "For web distributions, you can configure CloudFront to require that viewers use HTTPS to request your objects, so connections are encrypted when CloudFront communicates with viewers.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0020-CFR
#

default cf_min_protocol = null

aws_attribute_absence["cf_min_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.ViewerCertificate.MinimumProtocolVersion
}

aws_issue["cf_min_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cert := resource.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1"
}

aws_issue["cf_min_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cert := resource.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1_2016"
}

cf_min_protocol {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
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

cf_min_protocol_metadata := {
    "Policy Code": "PR-AWS-0020-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront web distribution that allow TLS versions 1.0 or lower",
    "Policy Description": "This policy identifies AWS CloudFront web distributions which are configured with TLS versions for HTTPS communication between viewers and CloudFront. As a best practice, use TLSv1.1_2016 or later as the minimum protocol version in your CloudFront distribution security policies.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0021-CFR
#

default cf_firewall = null

aws_attribute_absence["cf_firewall"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.WebACLId
}

aws_issue["cf_firewall"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.WebACLId) == 0
}

cf_firewall {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
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

cf_firewall_metadata := {
    "Policy Code": "PR-AWS-0021-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled",
    "Policy Description": "This policy identifies Amazon CloudFront web distributions which have the AWS Web Application Firewall (AWS WAF) service disabled. As a best practice, enable the AWS WAF service on CloudFront web distributions to protect against application layer attacks. To block malicious requests to your Cloudfront Content Delivery Network, define the block criteria in the WAF web access control list (web ACL).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0022-CFR
#

default cf_default_ssl = null

aws_issue["cf_default_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    resource.Properties.DistributionConfig.viewerCertificate.certificateSource
}

cf_default_ssl {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["cf_default_ssl"]
}

cf_default_ssl = false {
    aws_issue["cf_default_ssl"]
}

cf_default_ssl_err = "AWS CloudFront web distribution with default SSL certificate (deprecated)" {
    aws_issue["cf_default_ssl"]
}

cf_default_ssl_metadata := {
    "Policy Code": "PR-AWS-0022-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront web distribution with default SSL certificate",
    "Policy Description": "This policy identifies CloudFront web distributions which have a default SSL certificate to access CloudFront content. It is a best practice to use custom SSL Certificate to access CloudFront content. It gives you full control over the content data. custom SSL certificates also allow your users to access your content by using an alternate domain name. You can use a certificate stored in AWS Certificate Manager (ACM) or you can use a certificate stored in IAM.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0023-CFR
#

default cf_geo_restriction = null

aws_attribute_absence["cf_geo_restriction"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Restrictions.GeoRestriction.RestrictionType
}

aws_issue["cf_geo_restriction"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    lower(resource.Properties.DistributionConfig.Restrictions.GeoRestriction.RestrictionType) == "none"
}

cf_geo_restriction {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
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

cf_geo_restriction_metadata := {
    "Policy Code": "PR-AWS-0023-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudFront web distribution with geo restriction disabled",
    "Policy Description": "This policy identifies CloudFront web distributions which have geo restriction feature disabled. Geo Restriction has the ability to block IP addresses based on Geo IP by whitelist or blacklist a country in order to allow or restrict users in specific locations from accessing web application content.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

#
# PR-AWS-0024-CFR
#

default cf_s3_origin = null

aws_attribute_absence["cf_s3_origin"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Origins
}

aws_issue["cf_s3_origin"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(
        [c | count(resource.Properties.DistributionConfig.Origins[_].S3OriginConfig.OriginAccessIdentity) == 0; c := 1
    ]) > 0
}

cf_s3_origin {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
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

cf_s3_origin_metadata := {
    "Policy Code": "PR-AWS-0024-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail S3 buckets have not enabled MFA Delete",
    "Policy Description": "This policy identifies the S3 buckets which do not have Multi-Factor Authentication enabled for CloudTrails. For encryption of log files, CloudTrail defaults to use of S3 server-side encryption (SSE). We recommend adding an additional layer of security by adding MFA Delete to your S3 bucket. This will help to prevent deletion of CloudTrail logs without your explicit authorization. We also encourage you to use a bucket policy that places restrictions on which of your identity access management (IAM) users are allowed to delete S3 objects.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}
