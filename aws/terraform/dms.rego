package rule

# https://docs.amazonaws.cn/en_us/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-enginename
#
# PR-AWS-0207-TRF
#

default dms_endpoint = null

aws_issue["dms_endpoint"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dms_endpoint"
    lower(resource.properties.engine_name) != "s3"
    lower(resource.properties.ssl_mode) == "none"
}

aws_issue["dms_endpoint"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_dms_endpoint"
    lower(resource.properties.engine_name) != "s3"
    not resource.properties.ssl_mode
}

dms_endpoint {
    lower(input.resources[i].type) == "aws_dms_endpoint"
    not aws_issue["dms_endpoint"]
}

dms_endpoint = false {
    aws_issue["dms_endpoint"]
}

dms_endpoint_err = "Ensure DMS endpoints are supporting SSL configuration" {
    aws_issue["dms_endpoint"]
}

dms_endpoint_metadata := {
    "Policy Code": "PR-AWS-0207-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DMS endpoints are supporting SSL configuration",
    "Policy Description": "This policy identifies Database Migration Service (DMS) endpoints that are not configured with SSL to encrypt connections for source and target endpoints. It is recommended to use SSL connection for source and target endpoints; enforcing SSL connections help protect against 'man in the middle' attacks by encrypting the data stream between endpoint connections.\n\nNOTE: Not all databases use SSL in the same way. An Amazon Redshift endpoint already uses an SSL connection and does not require an SSL connection set up by AWS DMS. So there are some exlcusions included in policy RQL to report only those endpoints which can be configured using DMS SSL feature. \n\nFor more details:\nhttps://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#CHAP_Security.SSL",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.amazonaws.cn/en_us/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-enginename"
}
