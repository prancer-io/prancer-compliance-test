package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html

#
# PR-AWS-CFR-ACM-001
#

default acm_wildcard = null

aws_issue["acm_wildcard"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    not resource.Properties.DomainName
}

source_path[{"acm_wildcard": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    not resource.Properties.DomainName
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DomainName"]
        ],
    }
}

aws_issue["acm_wildcard"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(resource.Properties.DomainName, "*")
}

source_path[{"acm_wildcard": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(resource.Properties.DomainName, "*")
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DomainName"]
        ],
    }
}

aws_issue["acm_wildcard"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(resource.Properties.SubjectAlternativeNames[j], "*")
}

source_path[{"acm_wildcard": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(resource.Properties.SubjectAlternativeNames[j], "*")
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SubjectAlternativeNames", j]
        ],
    }
}

aws_issue["acm_wildcard"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(resource.Properties.DomainValidationOptions[j].DomainName, "*")
}

source_path[{"acm_wildcard": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    startswith(resource.Properties.DomainValidationOptions[j].DomainName, "*")
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "DomainValidationOptions", j, "DomainName"]
        ],
    }
}

acm_wildcard {
    lower(input.Resources[i].Type) == "aws::certificatemanager::certificate"
    not aws_issue["acm_wildcard"]
}

acm_wildcard = false {
    aws_issue["acm_wildcard"]
}

acm_wildcard_err = "AWS ACM Certificate with wildcard domain name" {
    aws_issue["acm_wildcard"]
}

acm_wildcard_metadata := {
    "Policy Code": "PR-AWS-CFR-ACM-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS ACM Certificate with wildcard domain name",
    "Policy Description": "This policy identifies ACM Certificates which are using wildcard certificates for wildcard domain name instead of single domain name certificates. ACM allows you to use an asterisk (*) in the domain name to create an ACM Certificate containing a wildcard name that can protect several sites in the same domain. For example, a wildcard certificate issued for *.<compliance-software>.io can match both www.<compliance-software>.io and images.<compliance-software>.io. When you use wildcard certificates, if the private key of a certificate is compromised, then all domain and subdomains that use the compromised certificate are potentially impacted. So it is recommended to use single domain name certificates instead of wildcard certificates to reduce the associated risks with a compromised domain or subdomain.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html"
}


#
# PR-AWS-CFR-ACM-002
#

default acm_ct_log = null

aws_issue["acm_ct_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    lower(resource.Properties.CertificateTransparencyLoggingPreference) != "enabled"
}

source_path[{"acm_ct_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::certificatemanager::certificate"
    lower(resource.Properties.CertificateTransparencyLoggingPreference) != "enabled"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "CertificateTransparencyLoggingPreference"]
        ],
    }
}

acm_ct_log {
    lower(input.Resources[i].Type) == "aws::certificatemanager::certificate"
    not aws_issue["acm_ct_log"]
}

acm_ct_log = false {
    aws_issue["acm_ct_log"]
}

acm_ct_log_err = "AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled" {
    aws_issue["acm_ct_log"]
}

acm_ct_log_metadata := {
    "Policy Code": "PR-AWS-CFR-ACM-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled",
    "Policy Description": "This policy identifies AWS Certificate Manager certificates in which Certificate Transparency Logging is disabled. AWS Certificate Manager (ACM) is the preferred tool to provision, manage, and deploy your server certificates. Certificate Transparency Logging is used to guard against SSL/TLS certificates that are issued by mistake or by a compromised CA, some browsers require that public certificates issued for your domain can also be recorded. This policy generates alerts for certificates which have transparency logging disabled. As a best practice, it is recommended to enable Transparency logging for all certificates.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html"
}


#
# PR-AWS-CFR-ACM-003
#

default acm_certificate_arn = null

aws_issue["acm_certificate_arn"] {
    resource := input.Resources[i]
    type = ["aws::certificatemanager::certificate", "aws::acmpca::certificate", "aws::acmpca::certificateauthorityactivation"]
    lower(resource.Type) == type[_]
    count(resource.Properties.CertificateAuthorityArn) == 0
}

source_path[{"acm_certificate_arn": metadata}] {
    resource := input.Resources[i]
    type = ["aws::certificatemanager::certificate", "aws::acmpca::certificate", "aws::acmpca::certificateauthorityactivation"]
    lower(resource.Type) == type[_]
    count(resource.Properties.CertificateAuthorityArn) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "CertificateAuthorityArn"]
        ],
    }
}

aws_issue["acm_certificate_arn"] {
    resource := input.Resources[i]
    type = ["aws::certificatemanager::certificate", "aws::acmpca::certificate", "aws::acmpca::certificateauthorityactivation"]
    lower(resource.Type) == type[_]
    resource.Properties.CertificateAuthorityArn == null
}

source_path[{"acm_certificate_arn": metadata}] {
    resource := input.Resources[i]
    type = ["aws::certificatemanager::certificate", "aws::acmpca::certificate", "aws::acmpca::certificateauthorityactivation"]
    lower(resource.Type) == type[_]
    resource.Properties.CertificateAuthorityArn == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "CertificateAuthorityArn"]
        ],
    }
}

acm_certificate_arn {
    type = ["aws::certificatemanager::certificate", "aws::acmpca::certificate", "aws::acmpca::certificateauthorityactivation"]
    not aws_issue["acm_certificate_arn"]
}

acm_certificate_arn = false {
    aws_issue["acm_certificate_arn"]
}

acm_certificate_arn_err = "Ensure that the CertificateManager certificates reference only Private ACMPCA certificate authorities" {
    aws_issue["acm_certificate_arn"]
}

acm_certificate_arn_metadata := {
    "Policy Code": "PR-AWS-CFR-ECS-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that the CertificateManager certificates reference only Private ACMPCA certificate authorities",
    "Policy Description": "Ensure that the aws certificate manager/ACMPCA Certificate CertificateAuthorityArn property references (using Fn::GetAtt or Ref) a Private CA, or that the property is not used.",
    "Resource Type": "aws::certificatemanager::certificate",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-certificatemanager-certificate.html#cfn-certificatemanager-certificate-certificateauthorityarn"
}
