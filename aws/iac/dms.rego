package rule

# https://docs.amazonaws.cn/en_us/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-enginename
#
# PR-AWS-0207-CFR
#

default dms_endpoint = null

aws_issue["dms_endpoint"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dms::endpoint"
    lower(resource.Properties.EngineName) != "s3"
    lower(resource.Properties.SslMode) == "none"
}

aws_issue["dms_endpoint"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dms::endpoint"
    lower(resource.Properties.EngineName) != "s3"
    not resource.Properties.SslMode
}

dms_endpoint {
    lower(input.Resources[i].Type) == "aws::dms::endpoint"
    not aws_issue["dms_endpoint"]
}

dms_endpoint = false {
    aws_issue["dms_endpoint"]
}

dms_endpoint_err = "Ensure DMS endpoints are supporting SSL configuration" {
    aws_issue["dms_endpoint"]
}

dms_endpoint_metadata := {
    "Policy Code": "PR-AWS-0207-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DMS endpoints are supporting SSL configuration",
    "Policy Description": "This policy identifies Database Migration Service (DMS) endpoints that are not configured with SSL to encrypt connections for source and target endpoints. It is recommended to use SSL connection for source and target endpoints; enforcing SSL connections help protect against 'man in the middle' attacks by encrypting the data stream between endpoint connections.\n\nNOTE: Not all databases use SSL in the same way. An Amazon Redshift endpoint already uses an SSL connection and does not require an SSL connection set up by AWS DMS. So there are some exlcusions included in policy RQL to report only those endpoints which can be configured using DMS SSL feature. \n\nFor more details:\nhttps://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#CHAP_Security.SSL",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.amazonaws.cn/en_us/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-enginename"
}


#
# PR-AWS-0350-CFR
#

default dms_public_access = null

aws_issue["dms_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dms::replicationinstance"
    lower(resource.Properties.PubliclyAccessible) != "false"
}

aws_bool_issue["dms_public_access"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dms::replicationinstance"
    resource.Properties.PubliclyAccessible == true
}

dms_public_access {
    lower(input.Resources[i].Type) == "aws::dms::replicationinstance"
    not aws_issue["dms_public_access"]
    not aws_bool_issue["dms_public_access"]
}

dms_public_access = false {
    aws_issue["dms_public_access"]
}

dms_public_access = false {
    aws_bool_issue["dms_public_access"]
}

dms_public_access_err = "Ensure DMS replication instance is not publicly accessible" {
    aws_issue["dms_public_access"]
} else = "Ensure DMS replication instance is not publicly accessible" {
    aws_bool_issue["dms_public_access"]
}

dms_public_access_metadata := {
    "Policy Code": "PR-AWS-0350-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DMS replication instance is not publicly accessible",
    "Policy Description": "Ensure DMS replication instance is not publicly accessible, this might cause sensitive data leak.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-publiclyaccessible"
}