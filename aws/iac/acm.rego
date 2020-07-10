package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html

#
# Id: 1
#

default acm_wildcard = null

acm_wildcard {
    lower(input.Type) == "aws::certificatemanager::certificate"
    not startswith(input.Properties.DomainName, "*")
    count([c | startswith(input.Properties.DomainValidationOptions[_].DomainName, "*"); c := 1]) == 0
}

acm_wildcard = false {
    lower(input.Type) == "aws::certificatemanager::certificate"
    startswith(input.Properties.DomainName, "*")
}

acm_wildcard = false {
    lower(input.Type) == "aws::certificatemanager::certificate"
    startswith(input.Properties.DomainValidationOptions[_].DomainName, "*")
}

acm_wildcard_err = "AWS ACM Certificate with wildcard domain name" {
    acm_wildcard == false
}

#
# Id: 9
#

default acm_ct_log = null

acm_ct_log {
    lower(input.Type) == "aws::certificatemanager::certificate"
    lower(input.Properties.CertificateTransparencyLoggingPreference) == "enabled"
}

acm_ct_log = false {
    lower(input.Type) == "aws::certificatemanager::certificate"
    lower(input.Properties.CertificateTransparencyLoggingPreference) != "enabled"
}

acm_ct_log = false {
    lower(input.Type) == "aws::certificatemanager::certificate"
    not input.Properties.CertificateTransparencyLoggingPreference
}

acm_ct_log_err = "AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled" {
    acm_ct_log == false
}
