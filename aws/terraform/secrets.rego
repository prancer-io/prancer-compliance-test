package rule

# PR-AWS-0028-RGX
#

default gl_aws_secrets = null

aws_issue["gl_aws_secrets"] {
    [path, value] := walk(input)
    regexp := "^[A-Za-z0-9/\\+=]{40}$"
    regex.match(regexp, format_int(value, 10))
    regex.match("^(?i)aws_?(secret)?_?(access)?_?key$", path[_])
}

aws_issue["gl_aws_secrets"] {
    [path, value] := walk(input)
    regexp := "^[A-Za-z0-9/\\+=]{40}$"
    regex.match(regexp, value)
    regex.match("^(?i)aws_?(secret)?_?(access)?_?key$", path[_])
}

gl_aws_secrets = false {
    aws_issue["gl_aws_secrets"]
}

gl_aws_secrets_err = "There is a possibility that AWS secret access key has leaked" {
    aws_issue["gl_aws_secrets"]
}

gl_aws_secrets_metadata := {
    "Policy Code": "PR-AWS-0028-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "There is a possibility that AWS secret access key has leaked",
    "Policy Description": "There is a possibility that AWS secret access key has leaked, template should not have any secret in it. Make sure to put the secrets in a vault",
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
    regexp := "^[0-9]{12}$"
    regex.match(regexp, format_int(value, 10))
    regex.match("^(?i)aws_?(account)_?(id)$", path[_])
}

aws_issue["gl_aws_account"] {
    [path, value] := walk(input)
    regexp := "^[0-9]{12}$"
    regex.match(regexp, value)
    regex.match("^(?i)aws_?(account)_?(id)$", path[_])
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
    "Language": "Terraform",
    "Policy Title": "There is a possibility that AWS account ID has leaked",
    "Policy Description": "There is a possibility that AWS account ID has leaked, template should not have any secret in it. Make sure to put the secrets in a vault",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": ""
}


#
# PR-AWS-0030-RGX
#

default al_access_key_id = null

aws_issue["al_access_key_id"] {
    [path, value] := walk(input)
    regexp := "^(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    regex.match(regexp, value)
    regex.match("^(?i)aws_?(access)_?(key)_?(id)_?$", path[_])
}

al_access_key_id = false {
    aws_issue["al_access_key_id"]
}

al_access_key_id_err = "There is a possibility that Aws access key id is exposed" {
    aws_issue["al_access_key_id"]
}

al_access_key_id_metadata := {
    "Policy Code": "PR-AWS-0030-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "There is a possibility that Aws access key id is exposed",
    "Policy Description": "There is a possibility that Aws access key id is exposed, template should not have any secret in it. Make sure to put the secrets in a vault",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": ""
}


#
# PR-AWS-0031-RGX
#

default al_mws = null

aws_issue["al_mws"] {
    [path, value] := walk(input)
    regexp := "(?i)amzn.mws.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    regex.match(regexp, value)
}

al_mws = false {
    aws_issue["al_mws"]
}

al_mws_err = "There is a possibility that Amazon Marketplace Web Service secret key is exposed" {
    aws_issue["al_mws"]
}

al_mws_metadata := {
    "Policy Code": "PR-AWS-0031-RGX",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "There is a possibility that Amazon Marketplace Web Service secret key is exposed",
    "Policy Description": "There is a possibility that Amazon Marketplace Web Service secret key is exposed. template should not have any secret in it. Make sure to put the secrets in a vault",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
