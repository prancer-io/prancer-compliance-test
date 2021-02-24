package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html

#
# PR-AWS-0001-CFR
#

default acm_wildcard = null

aws_attribute_absence["acm_wildcard"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    not resource.Properties.DomainName
}

aws_issue["acm_wildcard"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(resource.Properties.DomainName, "*")
}

aws_issue["acm_wildcard"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(resource.Properties.DomainValidationOptions[_].DomainName, "*")
}

acm_wildcard {
    lower(input.Resources[i].Type) == "aws::certificatemanager::certificate"
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

acm_wildcard_miss_err = "Certificate manager attribute DomainName missing in the resource" {
    aws_attribute_absence["acm_wildcard"]
}

#
# PR-AWS-0009-CFR
#

default acm_ct_log = null

aws_attribute_absence["acm_ct_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    not resource.Properties.CertificateTransparencyLoggingPreference
}

aws_issue["acm_ct_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    lower(resource.Properties.CertificateTransparencyLoggingPreference) != "enabled"
}

acm_ct_log {
    lower(input.Resources[i].Type) == "aws::certificatemanager::certificate"
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

acm_ct_log_miss_err = "Certificate manager attribute CertificateTransparencyLoggingPreference missing in the resource" {
    aws_attribute_absence["acm_ct_log"]
}
