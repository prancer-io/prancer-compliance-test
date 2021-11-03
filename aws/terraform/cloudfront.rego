package rule


#
# PR-AWS-TRF-CF-001
#

default cf_default_cache = null

aws_attribute_absence["cf_default_cache"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.default_cache_behavior
}

source_path[{"cf_default_cache": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.default_cache_behavior

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "default_cache_behavior"]
        ],
    }
}

aws_attribute_absence["cf_default_cache"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.default_cache_behavior) == 0
}

source_path[{"cf_default_cache": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.default_cache_behavior) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "default_cache_behavior"]
        ],
    }
}

aws_attribute_absence["cf_default_cache"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    default_cache_behavior := resource.properties.default_cache_behavior[j]
    not default_cache_behavior.field_level_encryption_id
}

source_path[{"cf_default_cache": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    default_cache_behavior := resource.properties.default_cache_behavior[j]
    not default_cache_behavior.field_level_encryption_id

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "default_cache_behavior", j, "field_level_encryption_id"]
        ],
    }
}

aws_issue["cf_default_cache"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    default_cache_behavior := resource.properties.default_cache_behavior[j]
    is_null(default_cache_behavior.field_level_encryption_id)
}

source_path[{"cf_default_cache": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    default_cache_behavior := resource.properties.default_cache_behavior[j]
    is_null(default_cache_behavior.field_level_encryption_id)

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "default_cache_behavior", j, "field_level_encryption_id"]
        ],
    }
}

aws_issue["cf_default_cache"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    default_cache_behavior := resource.properties.default_cache_behavior[j]
    count([c | default_cache_behavior.field_level_encryption_id == ""; c := 1]) > 0
}

source_path[{"cf_default_cache": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    default_cache_behavior := resource.properties.default_cache_behavior[j]
    count([c | default_cache_behavior.field_level_encryption_id == ""; c := 1]) > 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "default_cache_behavior", j, "field_level_encryption_id"]
        ],
    }
}

cf_default_cache {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
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
} else = "Cloudfront attribute DistributionConfig missing in the resource" {
    aws_attribute_absence["cf_default_cache"]
}

cf_default_cache_metadata := {
    "Policy Code": "PR-AWS-TRF-CF-001",
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
# PR-AWS-TRF-CF-002
#

default cf_ssl_protocol = null

aws_attribute_absence["cf_ssl_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    lower(viewer_certificate.minimum_protocol_version) == "sslv3"
}

source_path[{"cf_ssl_protocol": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    lower(viewer_certificate.minimum_protocol_version) == "sslv3"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "viewer_certificate", j, "minimum_protocol_version"]
        ],
    }
}

aws_issue["cf_ssl_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    custom_origin_config := origin.custom_origin_config[k]
    origin_ssl_protocols := custom_origin_config.origin_ssl_protocols[l]
    lower(origin_ssl_protocols) == "sslv3"
}

source_path[{"cf_ssl_protocol": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    custom_origin_config := origin.custom_origin_config[k]
    origin_ssl_protocols := custom_origin_config.origin_ssl_protocols[l]
    lower(origin_ssl_protocols) == "sslv3"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "origin", j, "custom_origin_config", k, "origin_ssl_protocols", l]
        ],
    }
}

cf_ssl_protocol {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
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
} else = "Cloudfront attribute origin_ssl_protocols missing in the resource" {
    aws_attribute_absence["cf_ssl_protocol"]
}

cf_ssl_protocol_metadata := {
    "Policy Code": "PR-AWS-TRF-CF-002",
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
# PR-AWS-TRF-CF-003
#

default cf_logging = null

aws_attribute_absence["cf_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    logging_config := resource.properties.logging_config[j]
    not logging_config.bucket    
}

source_path[{"cf_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    logging_config := resource.properties.logging_config[j]
    not logging_config.bucket

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging_config", j, "bucket"]
        ],
    }
}

aws_attribute_absence["cf_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.logging_config
}

source_path[{"cf_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.logging_config

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging_config"]
        ],
    }
}

aws_issue["cf_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.logging_config) == 0
}

source_path[{"cf_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.logging_config) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging_config"]
        ],
    }
}

aws_issue["cf_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    logging_config := resource.properties.logging_config[j]
    logging_config.bucket == null
}

source_path[{"cf_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    logging_config := resource.properties.logging_config[j]
    logging_config.bucket == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging_config", j, "bucket"]
        ],
    }
}

aws_issue["cf_logging"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    logging_config := resource.properties.logging_config[j]
    count([c | logging_config.bucket == ""; c := 1]) > 0
}

source_path[{"cf_logging": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    logging_config := resource.properties.logging_config[j]
    count([c | logging_config.bucket == ""; c := 1]) > 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "logging_config", j, "bucket"]
        ],
    }
}

cf_logging {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
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
} else = "Cloudfront attribute logging_config.bucket in the resource" {
    aws_attribute_absence["cf_logging"]
}

cf_logging_metadata := {
    "Policy Code": "PR-AWS-TRF-CF-003",
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
# PR-AWS-TRF-CF-004
#

default cf_https_only = null

aws_attribute_absence["cf_https_only"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    custom_origin_config := origin.custom_origin_config[k]
    not custom_origin_config.origin_protocol_policy
}

source_path[{"cf_https_only": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    custom_origin_config := origin.custom_origin_config[k]
    not custom_origin_config.origin_protocol_policy

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "origin", j, "custom_origin_config", k, "origin_protocol_policy"]
        ],
    }
}

aws_issue["cf_https_only"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    custom_origin_config := origin.custom_origin_config[k]
    custom_origin_config.origin_protocol_policy != "https-only"
}

source_path[{"cf_https_only": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    custom_origin_config := origin.custom_origin_config[k]
    custom_origin_config.origin_protocol_policy != "https-only"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "origin", j, "custom_origin_config", k, "origin_protocol_policy"]
        ],
    }
}

cf_https_only {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
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
} else = "Cloudfront attribute viewer_protocol_policy missing in the resource" {
    aws_attribute_absence["cf_https_only"]
}

cf_https_only_metadata := {
    "Policy Code": "PR-AWS-TRF-CF-004",
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
# PR-AWS-TRF-CF-005
#

default cf_https = null

aws_attribute_absence["cf_https"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    default_cache_behavior := resource.properties.default_cache_behavior[j]
    not default_cache_behavior.viewer_protocol_policy
}

source_path[{"cf_https": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    default_cache_behavior := resource.properties.default_cache_behavior[j]
    not default_cache_behavior.viewer_protocol_policy

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "default_cache_behavior", j, "viewer_protocol_policy"]
        ],
    }
}

aws_issue["cf_https"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    cache := resource.properties.default_cache_behavior[j]
    lower(cache.viewer_protocol_policy) != "https-only"
    lower(cache.viewer_protocol_policy) != "redirect-to-https"
}

source_path[{"cf_https": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    cache := resource.properties.default_cache_behavior[j]
    lower(cache.viewer_protocol_policy) != "https-only"
    lower(cache.viewer_protocol_policy) != "redirect-to-https"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "default_cache_behavior", j, "viewer_protocol_policy"]
        ],
    }
}

cf_https {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
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
} else = "Cloudfront attribute viewer_protocol_policy missing in the resource" {
    aws_attribute_absence["cf_https"]
}

cf_https_metadata := {
    "Policy Code": "PR-AWS-TRF-CF-005",
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
# PR-AWS-TRF-CF-006
#

default cf_min_protocol = null

aws_attribute_absence["cf_min_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    not viewer_certificate.minimum_protocol_version
}

source_path[{"cf_min_protocol": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    not viewer_certificate.minimum_protocol_version

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "viewer_certificate", j, "minimum_protocol_version"]
        ],
    }
}

aws_issue["cf_min_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    lower(viewer_certificate.minimum_protocol_version) == "tlsv1"
}

source_path[{"cf_min_protocol": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    lower(viewer_certificate.minimum_protocol_version) == "tlsv1"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "viewer_certificate", j, "minimum_protocol_version"]
        ],
    }
}

aws_issue["cf_min_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    lower(viewer_certificate.minimum_protocol_version) == "tlsv1_2016"
}

source_path[{"cf_min_protocol": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    lower(viewer_certificate.minimum_protocol_version) == "tlsv1_2016"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "viewer_certificate", j, "minimum_protocol_version"]
        ],
    }
}

cf_min_protocol {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
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
} else = "Cloudfront attribute minimum_protocol_version missing in the resource" {
    aws_attribute_absence["cf_min_protocol"]
}

cf_min_protocol_metadata := {
    "Policy Code": "PR-AWS-TRF-CF-006",
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
# PR-AWS-TRF-CF-007
#

default cf_firewall = null

aws_attribute_absence["cf_firewall"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.web_acl_id
}

source_path[{"cf_firewall": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.web_acl_id

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "web_acl_id"]
        ],
    }
}

aws_issue["cf_firewall"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.web_acl_id) == 0
}

source_path[{"cf_firewall": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    count(resource.properties.web_acl_id) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "web_acl_id"]
        ],
    }
}

cf_firewall {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
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
} else = "Cloudfront attribute web_acl_id missing in the resource" {
    aws_attribute_absence["cf_firewall"]
}

cf_firewall_metadata := {
    "Policy Code": "PR-AWS-TRF-CF-007",
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
# PR-AWS-TRF-CF-008
#

default cf_default_ssl = null

aws_issue["cf_default_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    lower(viewer_certificate.cloudfront_default_certificate) == "true"
}

source_path[{"cf_default_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    lower(viewer_certificate.cloudfront_default_certificate) == "true"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "viewer_certificate", j, "cloudfront_default_certificate"]
        ],
    }
}

aws_bool_issue["cf_default_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    viewer_certificate.cloudfront_default_certificate == true
}

source_path[{"cf_default_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    viewer_certificate := resource.properties.viewer_certificate[j]
    viewer_certificate.cloudfront_default_certificate == true

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "viewer_certificate", j, "cloudfront_default_certificate"]
        ],
    }
}

cf_default_ssl {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
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
    "Policy Code": "PR-AWS-TRF-CF-008",
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
# PR-AWS-TRF-CF-009
#

default cf_geo_restriction = null

aws_attribute_absence["cf_geo_restriction"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    restriction := resource.properties.restrictions[j]
    geo_restriction := restriction.geo_restriction[k]
    not geo_restriction.restriction_type
}

source_path[{"cf_geo_restriction": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    restriction := resource.properties.restrictions[j]
    geo_restriction := restriction.geo_restriction[k]
    not geo_restriction.restriction_type

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "restrictions", j, "geo_restriction", k, "restriction_type"]
        ],
    }
}

aws_issue["cf_geo_restriction"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    restriction := resource.properties.restrictions[j]
    geo_restriction := restriction.geo_restriction[k]
    lower(geo_restriction.restriction_type) == "none"
}

source_path[{"cf_geo_restriction": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    restriction := resource.properties.restrictions[j]
    geo_restriction := restriction.geo_restriction[k]
    lower(geo_restriction.restriction_type) == "none"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "restrictions", j, "geo_restriction", k, "restriction_type"]
        ],
    }
}

cf_geo_restriction {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
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
} else = "Cloudfront attribute geo restriction_type missing in the resource" {
    aws_attribute_absence["cf_geo_restriction"]
}

cf_geo_restriction_metadata := {
    "Policy Code": "PR-AWS-TRF-CF-009",
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
# PR-AWS-TRF-CF-010
#

default cf_s3_origin = null

aws_attribute_absence["cf_s3_origin"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.origin
}

source_path[{"cf_s3_origin": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    not resource.properties.origin

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "origin"]
        ],
    }
}

aws_attribute_absence["cf_s3_origin"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    not origin.s3_origin_config
}

source_path[{"cf_s3_origin": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    not origin.s3_origin_config

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "origin", j ,"s3_origin_config"]
        ],
    }
}

aws_attribute_absence["cf_s3_origin"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    count(origin.s3_origin_config) == 0
}

source_path[{"cf_s3_origin": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    count(origin.s3_origin_config) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "origin", j ,"s3_origin_config"]
        ],
    }
}

aws_issue["cf_s3_origin"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    s3_origin_config := origin.s3_origin_config[k]
    count(s3_origin_config.origin_access_identity) == 0
}

source_path[{"cf_s3_origin": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_cloudfront_distribution"
    origin := resource.properties.origin[j]
    s3_origin_config := origin.s3_origin_config[k]
    count(s3_origin_config.origin_access_identity) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "origin", j ,"s3_origin_config", k, "origin_access_identity"]
        ],
    }
}

cf_s3_origin {
    lower(input.resources[i].type) == "aws_cloudfront_distribution"
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
} else = "Cloudfront attribute origin_access_identity missing in the resource" {
    aws_attribute_absence["cf_s3_origin"]
}

cf_s3_origin_metadata := {
    "Policy Code": "PR-AWS-TRF-CF-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Cloudfront Distribution with S3 have Origin Access set to disabled",
    "Policy Description": "This policy identifies the AWS CloudFront distributions which are utilizing S3 bucket and have Origin Access Disabled. The origin access identity feature should be enabled for all your AWS CloudFront CDN distributions in order to restrict any direct access to your objects through Amazon S3 URLs.",
    "Resource Type": "aws_cloudfront_distribution",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-distribution.html"
}
