package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html

#
# PR-AWS-CFR-CF-001
#

default cf_default_cache = null

aws_issue["cf_default_cache"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId
}

source_path[{"cf_default_cache": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "DefaultCacheBehavior", "FieldLevelEncryptionId"]
        ],
    }
}

aws_issue["cf_default_cache"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId) == 0
}

source_path[{"cf_default_cache": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "DefaultCacheBehavior", "FieldLevelEncryptionId"]
        ],
    }
}

cf_default_cache {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["cf_default_cache"]
}

cf_default_cache = false {
    aws_issue["cf_default_cache"]
}

cf_default_cache_err = "AWS CloudFront Distributions with Field-Level Encryption not enabled" {
    aws_issue["cf_default_cache"]
}

cf_default_cache_metadata := {
    "Policy Code": "PR-AWS-CFR-CF-001",
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
# PR-AWS-CFR-CF-002
#

default cf_ssl_protocol = null

aws_issue["cf_ssl_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cert := resource.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "sslv3"
}

source_path[{"cf_ssl_protocol": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cert := resource.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "sslv3"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "ViewerCertificate", "MinimumProtocolVersion"]
        ],
    }
}

aws_issue["cf_ssl_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    origins := resource.Properties.DistributionConfig.Origins[j]
    lower(origins.CustomOriginConfig.OriginSSLProtocols[k]) == "sslv3"
}

source_path[{"cf_ssl_protocol": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    origins := resource.Properties.DistributionConfig.Origins[j]
    lower(origins.CustomOriginConfig.OriginSSLProtocols[k]) == "sslv3"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "Origins", j, "CustomOriginConfig", "OriginSSLProtocols", k]
        ],
    }
}

cf_ssl_protocol {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["cf_ssl_protocol"]
}

cf_ssl_protocol = false {
    aws_issue["cf_ssl_protocol"]
}

cf_ssl_protocol_err = "AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication" {
    aws_issue["cf_ssl_protocol"]
}

cf_ssl_protocol_metadata := {
    "Policy Code": "PR-AWS-CFR-CF-002",
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
# PR-AWS-CFR-CF-003
#

default cf_logging = null

aws_issue["cf_logging"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Logging.Bucket
}

source_path[{"cf_logging": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Logging.Bucket
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "Logging", "Bucket"]
        ],
    }
}

aws_issue["cf_logging"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.Logging.Bucket) == 0
}

source_path[{"cf_logging": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.Logging.Bucket) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "Logging", "Bucket"]
        ],
    }
}

cf_logging {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["cf_logging"]
}

cf_logging = false {
    aws_issue["cf_logging"]
}

cf_logging_err = "AWS CloudFront distribution with access logging disabled" {
    aws_issue["cf_logging"]
}

cf_logging_metadata := {
    "Policy Code": "PR-AWS-CFR-CF-003",
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
# PR-AWS-CFR-CF-004
#

default cf_https_only = null

aws_issue["cf_https_only"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(
        [c | lower(resource.Properties.DistributionConfig.Origins[_].CustomOriginConfig.OriginProtocolPolicy) != "https-only"; c := 1
    ]) > 0
}

source_path[{"cf_https_only": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    origin := resource.Properties.DistributionConfig.Origins[j]
    lower(origin.CustomOriginConfig.OriginProtocolPolicy) != "https-only"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "Origins", j, "CustomOriginConfig", "OriginProtocolPolicy"]
        ],
    }
}

cf_https_only {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["cf_https_only"]
}

cf_https_only = false {
    aws_issue["cf_https_only"]
}

cf_https_only_err = "AWS CloudFront origin protocol policy does not enforce HTTPS-only" {
    aws_issue["cf_https_only"]
}

cf_https_only_metadata := {
    "Policy Code": "PR-AWS-CFR-CF-004",
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
# PR-AWS-CFR-CF-005
#

default cf_https = null

aws_attribute_absence["cf_https"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy
}

source_path[{"cf_https": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "DefaultCacheBehavior", "ViewerProtocolPolicy"]
        ],
    }
}

aws_issue["cf_https"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cache := resource.Properties.DistributionConfig.DefaultCacheBehavior
    lower(cache.ViewerProtocolPolicy) != "https-only"
    lower(cache.ViewerProtocolPolicy) != "redirect-to-https"
}

source_path[{"cf_https": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cache := resource.Properties.DistributionConfig.DefaultCacheBehavior
    lower(cache.ViewerProtocolPolicy) != "https-only"
    lower(cache.ViewerProtocolPolicy) != "redirect-to-https"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "DefaultCacheBehavior", "ViewerProtocolPolicy"]
        ],
    }
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
} else = "AWS CloudFront viewer protocol policy is not configured with HTTPS" {
    aws_attribute_absence["cf_https"]
}

cf_https_metadata := {
    "Policy Code": "PR-AWS-CFR-CF-005",
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
# PR-AWS-CFR-CF-006
#

default cf_min_protocol = null

aws_issue["cf_min_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cert := resource.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1"
}

source_path[{"cf_min_protocol": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cert := resource.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "ViewerCertificate", "MinimumProtocolVersion"]
        ],
    }
}

aws_issue["cf_min_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cert := resource.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1_2016"
}

source_path[{"cf_min_protocol": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    cert := resource.Properties.DistributionConfig.ViewerCertificate
    lower(cert.MinimumProtocolVersion) == "tlsv1_2016"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "ViewerCertificate", "MinimumProtocolVersion"]
        ],
    }
}

cf_min_protocol {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["cf_min_protocol"]
}

cf_min_protocol = false {
    aws_issue["cf_min_protocol"]
}

cf_min_protocol_err = "AWS CloudFront web distribution that allow TLS versions 1.0 or lower" {
    aws_issue["cf_min_protocol"]
}

cf_min_protocol_metadata := {
    "Policy Code": "PR-AWS-CFR-CF-006",
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
# PR-AWS-CFR-CF-007
#

default cf_firewall = null

aws_issue["cf_firewall"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.WebACLId
}

source_path[{"cf_firewall": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.WebACLId
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "WebACLId"]
        ],
    }
}

aws_issue["cf_firewall"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.WebACLId) == 0
}

source_path[{"cf_firewall": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    count(resource.Properties.DistributionConfig.WebACLId) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "WebACLId"]
        ],
    }
}

cf_firewall {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["cf_firewall"]
}

cf_firewall = false {
    aws_issue["cf_firewall"]
}

cf_firewall_err = "AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled" {
    aws_issue["cf_firewall"]
}

cf_firewall_metadata := {
    "Policy Code": "PR-AWS-CFR-CF-007",
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
# PR-AWS-CFR-CF-008
#

default cf_default_ssl = null

aws_issue["cf_default_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    lower(resource.Properties.DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate) == "true"
}

source_path[{"cf_default_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    lower(resource.Properties.DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate) == "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "ViewerCertificate", "CloudFrontDefaultCertificate"]
        ],
    }
}

aws_bool_issue["cf_default_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    resource.Properties.DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate == true
}

source_path[{"cf_default_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    resource.Properties.DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate == true
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "ViewerCertificate", "CloudFrontDefaultCertificate"]
        ],
    }
}

cf_default_ssl {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["cf_default_ssl"]
    not aws_bool_issue["cf_default_ssl"]
}

cf_default_ssl = false {
    aws_issue["cf_default_ssl"]
}

cf_default_ssl = false {
    aws_bool_issue["cf_default_ssl"]
}

cf_default_ssl_err = "AWS CloudFront web distribution with default SSL certificate (deprecated)" {
    aws_issue["cf_default_ssl"]
} else = "AWS CloudFront web distribution with default SSL certificate (deprecated)" {
    aws_bool_issue["cf_default_ssl"]
}

cf_default_ssl_metadata := {
    "Policy Code": "PR-AWS-CFR-CF-008",
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
# PR-AWS-CFR-CF-009
#

default cf_geo_restriction = null

aws_issue["cf_geo_restriction"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Restrictions
}

source_path[{"cf_geo_restriction": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    not resource.Properties.DistributionConfig.Restrictions
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "Restrictions"]
        ],
    }
}

aws_issue["cf_geo_restriction"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    lower(resource.Properties.DistributionConfig.Restrictions.GeoRestriction.RestrictionType) == "none"
}

source_path[{"cf_geo_restriction": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    lower(resource.Properties.DistributionConfig.Restrictions.GeoRestriction.RestrictionType) == "none"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DistributionConfig", "Restrictions", "GeoRestriction", "RestrictionType"]
        ],
    }
}

cf_geo_restriction {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["cf_geo_restriction"]
}

cf_geo_restriction = false {
    aws_issue["cf_geo_restriction"]
}

cf_geo_restriction_err = "AWS CloudFront web distribution with geo restriction disabled" {
    aws_issue["cf_geo_restriction"]
}

cf_geo_restriction_metadata := {
    "Policy Code": "PR-AWS-CFR-CF-009",
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
# PR-AWS-CFR-CF-010
#

default cf_s3_origin = null

aws_issue["cf_s3_origin"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    origin := resource.Properties.DistributionConfig.Origins[_]
    origin.S3OriginConfig
    origin.S3OriginConfig.OriginAccessIdentity == ""
}

aws_issue["cf_s3_origin"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    origin := resource.Properties.DistributionConfig.Origins[_]
    origin.S3OriginConfig
    origin.S3OriginConfig.OriginAccessIdentity == null
}

aws_issue["cf_s3_origin"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::cloudfront::distribution"
    origin := resource.Properties.DistributionConfig.Origins[_]
    origin.S3OriginConfig
    not origin.S3OriginConfig.OriginAccessIdentity
}

cf_s3_origin {
    lower(input.Resources[i].Type) == "aws::cloudfront::distribution"
    not aws_issue["cf_s3_origin"]
}

cf_s3_origin = false {
    aws_issue["cf_s3_origin"]
}

cf_s3_origin_err = "AWS Cloudfront Distribution with S3 have Origin Access set to disabled" {
    aws_issue["cf_s3_origin"]
}

cf_s3_origin_metadata := {
    "Policy Code": "PR-AWS-CFR-CF-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Cloudfront Distribution with S3 have Origin Access set to disabled",
    "Policy Description": "This policy identifies the AWS CloudFront distributions which are utilizing S3 bucket and have Origin Access Disabled. The origin access identity feature should be enabled for all your AWS CloudFront CDN distributions in order to restrict any direct access to your objects through Amazon S3 URLs.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}

