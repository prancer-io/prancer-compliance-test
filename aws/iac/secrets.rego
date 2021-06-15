package rule

# PR-AWS-0028-RGX
#

default gl_aws_secrets = null

aws_issue["gl_aws_secrets"] {
    [path, value] := walk(input)
    regexp := "[0-9a-z]{32}"
    regex.match(regexp, value)
    regex.match("(?i)aws_?(secret)?_?(access)?_?key", path[_])
}

aws_issue["gl_aws_secrets"] {
    [path, value] := walk(input)
    regexp := "[A-Za-z0-9/\\+=]{40}"
    regex.match(regexp, value)
}

gl_aws_secrets = false {
    aws_issue["gl_aws_secrets"]
}

gl_aws_secrets_err = "There is a possibility that AWS secret has leaked" {
    aws_issue["gl_aws_secrets"]
}

gl_aws_secrets_metadata := {
    "Policy Code": "PR-AWS-0028-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail logs are not encrypted using Customer Master Keys (CMKs)",
    "Policy Description": "Checks to ensure that CloudTrail logs are encrypted. AWS CloudTrail is a service that enables governance, compliance, operational PR-AWS-0028-RGX-DESC risk auditing of the AWS account. It is a compliance and security best practice to encrypt the CloudTrail data since it may contain sensitive information.",
    "Compliance": ["CIS","CSA-CCM","GDPR","HITRUST","ISO 27001","NIST 800"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": ""
}

#
# PR-AWS-0029-RGX
#

default gl_aws_account = null

aws_issue["gl_aws_account"] {
    [path, value] := walk(input)
    regexp := "[0-9a-z]{32}"
    regex.match(regexp, value)
    regex.match("((?i)aws_?(account)_?(id)?", path[_])
}

aws_issue["gl_aws_account"] {
    [path, value] := walk(input)
    regexp := "[0-9]{4}\\-?[0-9]{4}\\-?[0-9]{4}"
    regex.match(regexp, value)
}

gl_aws_account = false {
    aws_issue["gl_aws_account"]
}

gl_aws_account_err = "There is a possibility that AWS account ID has leaked" {
    aws_issue["gl_aws_account"]
}

gl_aws_account_metadata := {
    "Policy Code": "PR-AWS-0029-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS CloudTrail logs should integrate with CloudWatch for all regions",
    "Policy Description": "This policy identifies the Cloudtrails which is not integrated with cloudwatch for all regions. CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs within a specified S3 bucket for long term analysis, realtime analysis can be performed by configuring CloudTrail to send logs to CloudWatch Logs. For a trail that is enabled in all regions in an account, CloudTrail sends log files from all those regions to a CloudWatch Logs log group. It is recommended that CloudTrail logs be sent to CloudWatch Logs.",
    "Compliance": ["CSA-CCM","GDPR","HITRUST","ISO 27001","NIST 800","SOC 2"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
