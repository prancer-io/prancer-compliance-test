package rule

# PR-AWS-0028-RGX
#

default gl_aws_secrets = null

aws_issue["gl_aws_secrets"] {
    [path, value] := walk(input)
    regexp := "[0-9a-zA-Z/\\]{32}"
    regex.match(regexp, value)
    regex.match("(?i)aws_?(secret)?_?(access)?_?key", path[_])
}

aws_issue["gl_aws_secrets"] {
    [path, value] := walk(input)
    regexp := "^[A-Za-z0-9/\\+=]{40}$"
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
    "Policy Title": "Secrets should be removed from the source code",
    "Policy Description": "We should not have any secret in the source code. Make sure to put the secrets in a vault",
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
    regexp := "[0-9a-zA-Z/\\]{32}"
    regex.match(regexp, value)
    regex.match("((?i)aws_?(account)_?(id)?", path[_])
}

aws_issue["gl_aws_account"] {
    [path, value] := walk(input)
    regexp := "^[0-9]{4}\\-?[0-9]{4}\\-?[0-9]{4}$"
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
    "Policy Title": "Secrets should be removed from the source code",
    "Policy Description": "We should not have any secret in the source code. Make sure to put the secrets in a vault",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
