package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html

#
# PR-AWS-CLD-ACM-001
#

default acm_wildcard = true

acm_wildcard = false {
    # lower(resource.Type) == "aws::certificatemanager::certificate"
    not input.Certificate.DomainName
}

acm_wildcard = false {
    # lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(input.Certificate.DomainName, "*")
}

acm_wildcard = false {
    # lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(input.Certificate.SubjectAlternativeNames[_], "*")
}

acm_wildcard = false {
    # lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(input.Certificate.DomainValidationOptions[_].DomainName, "*")
}

acm_wildcard_err = "AWS ACM Certificate with wildcard domain name" {
    not acm_wildcard
}

acm_wildcard_metadata := {
    "Policy Code": "PR-AWS-CLD-ACM-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS ACM Certificate with wildcard domain name",
    "Policy Description": "This policy identifies ACM Certificates which are using wildcard certificates for wildcard domain name instead of single domain name certificates. ACM allows you to use an asterisk (*) in the domain name to create an ACM Certificate containing a wildcard name that can protect several sites in the same domain. For example, a wildcard certificate issued for *.<compliance-software>.io can match both www.<compliance-software>.io and images.<compliance-software>.io. When you use wildcard certificates, if the private key of a certificate is compromised, then all domain and subdomains that use the compromised certificate are potentially impacted. So it is recommended to use single domain name certificates instead of wildcard certificates to reduce the associated risks with a compromised domain or subdomain.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html"
}


#
# PR-AWS-CLD-ACM-002
#

default acm_ct_log = true

acm_ct_log = false {
    # lower(resource.Type) == "aws::certificatemanager::certificate"
    lower(input.Certificate.Options.CertificateTransparencyLoggingPreference) != "enabled"
}

acm_ct_log_err = "AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled" {
    not acm_ct_log
}

acm_ct_log_metadata := {
    "Policy Code": "PR-AWS-CLD-ACM-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled",
    "Policy Description": "This policy identifies AWS Certificate Manager certificates in which Certificate Transparency Logging is disabled. AWS Certificate Manager (ACM) is the preferred tool to provision, manage, and deploy your server certificates. Certificate Transparency Logging is used to guard against SSL/TLS certificates that are issued by mistake or by a compromised CA, some browsers require that public certificates issued for your domain can also be recorded. This policy generates alerts for certificates which have transparency logging disabled. As a best practice, it is recommended to enable Transparency logging for all certificates.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html"
}


#
# PR-AWS-CLD-ACM-003
#

default acm_certificate_arn = true

acm_certificate_arn = false {
    # type = ["aws::certificatemanager::certificate", "aws::acmpca::certificate", "aws::acmpca::certificateauthorityactivation"]
    # lower(resource.Type) == type[_]
    not input.Certificate.CertificateAuthorityArn
}

acm_certificate_arn = false {
    # type = ["aws::certificatemanager::certificate", "aws::acmpca::certificate", "aws::acmpca::certificateauthorityactivation"]
    # lower(resource.Type) == type[_]
    count(input.Certificate.CertificateAuthorityArn) == 0
}

acm_certificate_arn = false{
    # type = ["aws::certificatemanager::certificate", "aws::acmpca::certificate", "aws::acmpca::certificateauthorityactivation"]
    # lower(resource.Type) == type[_]
    input.Certificate.CertificateAuthorityArn == null
}

acm_certificate_arn_err = "Ensure that the CertificateManager certificates reference only Private ACMPCA certificate authorities" {
    not acm_certificate_arn
}

acm_certificate_arn_metadata := {
    "Policy Code": "PR-AWS-CLD-ACM-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that the CertificateManager certificates reference only Private ACMPCA certificate authorities",
    "Policy Description": "Ensure that the aws certificate manager/ACMPCA Certificate CertificateAuthorityArn property references (using Fn::GetAtt or Ref) a Private CA, or that the property is not used.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-certificateauthorityarn"
}


#
# PR-AWS-CLD-ACM-005
#

default acm_do_not_have_unused_certificate = true         

acm_do_not_have_unused_certificate = false {
    # lower(resource.Type) == "aws::certificatemanager::certificate"
    not input.Certificate.InUseBy
}

acm_do_not_have_unused_certificate = false {
    # lower(resource.Type) == "aws::certificatemanager::certificate"
    count(input.Certificate.InUseBy) == 0
}

acm_do_not_have_unused_certificate_err = "Ensure Certificate Manager (ACM) does not have unused certificates." {
    not acm_do_not_have_unused_certificate
}

acm_do_not_have_unused_certificate_metadata := {
    "Policy Code": "PR-AWS-CLD-ACM-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Certificate Manager (ACM) does not have unused certificates.",
    "Policy Description": "It checks if the ACM certificates provisioned are not left unused in ACM.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.describe_certificate"
}

#
# PR-AWS-CLD-ACM-006
#

default acm_do_not_have_certificate_pending_validation = true

acm_do_not_have_certificate_pending_validation = false {
    # lower(resource.Type) == "aws::certificatemanager::certificate"
    lower(input.Certificate.Status) == "pending_validation"
}


acm_do_not_have_certificate_pending_validation_err = "Ensure AWS Certificate Manager (ACM) does not contain certificate pending validation." {
    not acm_do_not_have_certificate_pending_validation
}

acm_do_not_have_certificate_pending_validation_metadata := {
    "Policy Code": "PR-AWS-CLD-ACM-006",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Certificate Manager (ACM) does not contain certificate pending validation.",
    "Policy Description": "This policy identifies invalid certificates which are in AWS Certificate Manager. When your Amazon ACM certificates are not validated within 72 hours after the request is made, those certificates become invalid and you will have to request new certificates, which could cause interruption to your applications or services. Though AWS Certificate Manager automatically renews certificates issued by the service that is used with other AWS resources. However, the ACM service does not automatically renew certificates that are not currently in use or not associated anymore with other AWS resources. So the renewal process including validation must be done manually before these certificates become invalid.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.describe_certificate"
}

#
# PR-AWS-CLD-ACM-007
#

default acm_do_not_have_invalid_or_failed = true

certificate_invalid_or_failed_status := ["validation_timed_out", "failed"]

acm_do_not_have_invalid_or_failed = false {
    # lower(resource.Type) == "aws::certificatemanager::certificate"
    lower(input.Certificate.Status) == certificate_invalid_or_failed_status[_]
}


acm_do_not_have_invalid_or_failed_err = "Ensure AWS Certificate Manager (ACM) does not have invalid or failed certificate." {
    not acm_do_not_have_invalid_or_failed
}

acm_do_not_have_invalid_or_failed_metadata := {
    "Policy Code": "PR-AWS-CLD-ACM-007",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Certificate Manager (ACM) does not have invalid or failed certificate.",
    "Policy Description": "This policy identifies certificates in ACM which are either in Invalid or Failed state. If the ACM certificate is not validated within 72 hours, it becomes Invalid. In such cases (Invalid or Failed certificate), you will have to request for a new certificate. It is strongly recommended to delete the certificates which are in failed or invalid state.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.describe_certificate"
}


#
# PR-AWS-CLD-ACM-008
# aws::certificatemanager::certificate"

default acm_expiring_certificate = true

acm_expiring_certificate = false {
    lower(input.Certificate.Status) == "issued"
    exp_timestamp := input.Certificate.NotAfter["$date"]
    exp_timestamp_nanosecond := exp_timestamp * 1000000
    current_date_timestamp := time.now_ns()
	(exp_timestamp_nanosecond - current_date_timestamp) < 2678400000000000
}

acm_expiring_certificate_err = "Ensure AWS Certificate Manager (ACM) does not have certificates expiring in 30 days or less." {
    not acm_expiring_certificate
}

acm_expiring_certificate_metadata := {
    "Policy Code": "PR-AWS-CLD-ACM-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Certificate Manager (ACM) does not have certificates expiring in 30 days or less.",
    "Policy Description": "It identifies ACM certificates expiring in 30 days or less, which are in the AWS Certificate Manager. If SSL/TLS certificates are not renewed prior to their expiration date, they will become invalid and the communication between the client and the AWS resource that implements the certificates is no longer secure. As a best practice, it is recommended to renew certificates before their validity period ends. AWS Certificate Manager automatically renews certificates issued by the service that is used with other AWS resources. However, the ACM service does not renew automatically certificates that are not in use or not associated anymore with other AWS resources. So the renewal process must be done manually before these certificates become invalid. NOTE: If you wanted to be notified other than before or less than 30 days; you can clone this policy and replace '30' in RQL with your desired days value. For example, 15 days OR 7 days which will alert certificates expiring in 15 days or less OR 7 days or less respectively.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.describe_certificate"
}


#
# PR-AWS-CLD-ACM-009
# aws::certificatemanager::certificate"

default acm_expired_certificates = true

acm_expired_certificates = false {
    lower(input.Certificate.Status) == "expired"
    exp_timestamp := input.Certificate.NotAfter["$date"]
    exp_timestamp_nanosecond := exp_timestamp * 1000000
    current_date_timestamp := time.now_ns()
	(exp_timestamp_nanosecond - current_date_timestamp) < -1
}

acm_expired_certificates_err = "Ensure AWS Certificate Manager (ACM) does not have expired certificates." {
    not acm_expired_certificates
}

acm_expired_certificates_metadata := {
    "Policy Code": "PR-AWS-CLD-ACM-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS Certificate Manager (ACM) does not have expired certificates.",
    "Policy Description": "It identifies expired certificates which are in AWS Certificate Manager. AWS Certificate Manager (ACM) is the preferred tool to provision, manage, and deploy your server certificates. With ACM you can request a certificate or deploy an existing ACM or external certificate to AWS resources. This policy generates alerts if there are any expired ACM managed certificates. As a best practice, it is recommended to delete expired certificates.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.describe_certificate"
}