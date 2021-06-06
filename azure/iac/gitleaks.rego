package rule

#
# PR-AZR-0001-RGX
#

default gl_azure_secrets = null

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]onmicrosoft[.]com"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]blob[.]core[.]windows[.]net"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]queue[.]core[.]windows[.]net"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]table[.]core[.]windows[.]net"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]database[.]windows[.]net"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]servicebus[.]windows[.]net"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]timeseries[.]azure[.]com"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]accesscontrol[.]windows[.]net"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]azurehdinsight[.]net"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]cloudapp[.]azure[.]com"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]cloudapp[.]net"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "(?i).*[0-9a-zA-Z]{2,256}[.]documents[.]azure[.]com"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "^-----BEGIN (RSA|EC|DSA|GPP) PRIVATE KEY-----$"
    regex.match(regexp, value)
}

azure_issue["gl_azure_secrets"] {
    [path, value] := walk(input)
    regexp := "^-----BEGIN (RSA|EC|DSA|GPP) PRIVATE KEY-----$"
    regex.match(regexp, value)
}

gl_azure_secrets = false {
    azure_issue["gl_azure_secrets"]
}

gl_azure_secrets_err = "There is a possibility that Azure secret has leaked" {
    azure_issue["gl_azure_secrets"]
}

gl_azure_secrets_metadata := {
    "Policy Code": "PR-AZR-0001-RGX",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "AWS Cloud formation",
    "Policy Title": "Activity Log Retention should not be set to less than 365 days",
    "Policy Description": "A Log Profile controls how your Activity Log is exported and retained. Since the average time to detect a breach is over 200 days, it is recommended to retain your activity log for 365 days or more in order to have time to respond to any incidents.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
