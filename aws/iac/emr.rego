package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration
#
# PR-AWS-0216-CFR
#

default emr_security = null

aws_issue["emr_security"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    not resource.Properties.SecurityConfiguration
}

aws_issue["emr_security"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    count(resource.Properties.SecurityConfiguration) == 0
}

aws_issue["emr_security"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    resource.Properties.SecurityConfiguration == null
}

emr_security {
    lower(input.Resources[i].Type) == "aws::emr::cluster"
    not aws_issue["emr_security"]
}

emr_security = false {
    aws_issue["emr_security"]
}

emr_security = "Ensure AWS EMR cluster is configured with security configuration" {
    aws_issue["emr_security"]
}

emr_security_metadata := {
    "Policy Code": "PR-AWS-0216-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure AWS EMR cluster is configured with security configuration",
    "Policy Description": "Ensure AWS EMR cluster is configured with security configuration",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration"
}


#
# PR-AWS-0217-CFR
#

default emr_kerberos = null

aws_issue["emr_kerberos"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    not resource.Properties.KerberosAttributes.Realm
}

aws_issue["emr_kerberos"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    resource.Properties.KerberosAttributes.Realm == null
}

aws_issue["emr_kerberos"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::emr::cluster"
    count(resource.Properties.KerberosAttributes.Realm) == 0
}

emr_kerberos {
    lower(input.Resources[i].Type) == "aws::emr::cluster"
    not aws_issue["emr_kerberos"]
}

emr_kerberos = false {
    aws_issue["emr_kerberos"]
}

emr_kerberos = "Must use kerberized auth for internal communications within the cluster" {
    aws_issue["emr_kerberos"]
}

emr_kerberos_metadata := {
    "Policy Code": "PR-AWS-0217-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Must use kerberized auth for internal communications within the cluster",
    "Policy Description": "Must use kerberized auth for internal communications within the cluster",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-kerberosattributes"
}
