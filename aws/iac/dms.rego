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

dms_endpoint = "Ensure DMS endpoint are SSL configured" {
    aws_issue["dms_endpoint"]
}

dms_endpoint_metadata := {
    "Policy Code": "PR-AWS-0207-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DMS endpoint are SSL configured",
    "Policy Description": "Ensure DMS endpoint are SSL configured",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.amazonaws.cn/en_us/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html#cfn-dms-endpoint-enginename"
}
