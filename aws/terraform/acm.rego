package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html

#
# PR-AWS-0001-TRF
#

default acm_wildcard = null

aws_attribute_absence["acm_wildcard"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    not resource.properties.domain_name
}

aws_issue["acm_wildcard"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    startswith(resource.properties.domain_name, "*")
}

aws_issue["acm_wildcard"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    startswith(resource.properties.DomainValidationOptions[_].domain_name, "*")
}

acm_wildcard {
    lower(input.json.resources[_].type) == "aws_acm_certificate"
    not aws_issue["acm_wildcard"]
    not aws_attribute_absence["acm_wildcard"]
}

acm_wildcard = false {
    aws_issue["acm_wildcard"]
}

acm_wildcard = false {
    aws_attribute_absence["acm_wildcard"]
}

acm_wildcard_err = "AWS ACM Certificate with wildcard domain name" {
    aws_issue["acm_wildcard"]
}

acm_wildcard_miss_err = "Certificate manager attribute domain_name missing in the resource" {
    aws_attribute_absence["acm_wildcard"]
}

#
# PR-AWS-0009-TRF
#

default acm_ct_log = null

aws_attribute_absence["acm_ct_log"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    not resource.properties.certificate_transparency_logging_preference
}

aws_issue["acm_ct_log"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    lower(resource.properties.certificate_transparency_logging_preference) != "enabled"
}

acm_ct_log {
    lower(input.json.resources[_].type) == "aws_acm_certificate"
    not aws_issue["acm_ct_log"]
    not aws_attribute_absence["acm_ct_log"]
}

acm_ct_log = false {
    aws_issue["acm_ct_log"]
}

acm_ct_log = false {
    aws_attribute_absence["acm_ct_log"]
}

acm_ct_log_err = "AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled" {
    aws_issue["acm_ct_log"]
}

acm_ct_log_miss_err = "Certificate manager attribute certificate_transparency_logging_preference missing in the resource" {
    aws_attribute_absence["acm_ct_log"]
}
