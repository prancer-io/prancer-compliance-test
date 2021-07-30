package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html

#
# PR-AWS-0001-TRF
#

default acm_wildcard = null

aws_issue["acm_wildcard"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    not resource.properties.domain_name
    not resource.properties.private_key
}

aws_issue["acm_wildcard"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    startswith(resource.properties.domain_name, "*")
}

aws_issue["acm_wildcard"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    startswith(resource.properties.subject_alternative_names[_], "*")
}

aws_issue["acm_wildcard"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    domain_validation_options := resource.properties.DomainValidationOptions[_]
    startswith(domain_validation_options.domain_name, "*")
}

acm_wildcard {
    lower(input.resources[_].type) == "aws_acm_certificate"
    not aws_issue["acm_wildcard"]
}

acm_wildcard = false {
    aws_issue["acm_wildcard"]
}

acm_wildcard_err = "AWS ACM Certificate with wildcard domain name" {
    aws_issue["acm_wildcard"]
}

acm_wildcard_metadata := {
    "Policy Code": "PR-AWS-0001-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS ACM Certificate with wildcard domain name",
    "Policy Description": "This policy identifies ACM Certificates which are using wildcard certificates for wildcard domain name instead of single domain name certificates. ACM allows you to use an asterisk (*) in the domain name to create an ACM Certificate containing a wildcard name that can protect several sites in the same domain. For example, a wildcard certificate issued for *.<compliance-software>.io can match both www.<compliance-software>.io and images.<compliance-software>.io. When you use wildcard certificates, if the private key of a certificate is compromised, then all domain and subdomains that use the compromised certificate are potentially impacted. So it is recommended to use single domain name certificates instead of wildcard certificates to reduce the associated risks with a compromised domain or subdomain.",
    "Resource Type": "aws_acm_certificate",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html"
}

#
# PR-AWS-0009-TRF
#

default acm_ct_log = null

aws_attribute_absence["acm_ct_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    not resource.properties.options
}

aws_attribute_absence["acm_ct_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    count(resource.properties.options) == 0
}

aws_attribute_absence["acm_ct_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    option := resource.properties.options[_]
    not option.certificate_transparency_logging_preference
}

aws_issue["acm_ct_log"] {
    resource := input.resources[_]
    lower(resource.type) == "aws_acm_certificate"
    option := resource.properties.options[_]
    lower(option.certificate_transparency_logging_preference) != "enabled"
}

acm_ct_log {
    lower(input.resources[_].type) == "aws_acm_certificate"
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

acm_ct_log_metadata := {
    "Policy Code": "PR-AWS-0009-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled",
    "Policy Description": "This policy identifies AWS Certificate Manager certificates in which Certificate Transparency Logging is disabled. AWS Certificate Manager (ACM) is the preferred tool to provision, manage, and deploy your server certificates. Certificate Transparency Logging is used to guard against SSL/TLS certificates that are issued by mistake or by a compromised CA, some browsers require that public certificates issued for your domain can also be recorded. This policy generates alerts for certificates which have transparency logging disabled. As a best practice, it is recommended to enable Transparency logging for all certificates.",
    "Resource Type": "aws_acm_certificate",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html"
}
