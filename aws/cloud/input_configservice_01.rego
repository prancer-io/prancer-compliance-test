#
# PR-AWS-0033
#

package rule

default rulepass = false

rulepass = true {
    input.ConfigurationRecorders[_].recordingGroup.allSupported=true
    input.ConfigurationRecorders[_].recordingGroup.includeGlobalResourceTypes=true
}

metadata := {
    "Policy Code": "PR-AWS-0033",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Config must record all possible resources",
    "Policy Description": "This policy identifies resources for which AWS Config recording is enabled but recording for all possible resources are disabled. AWS Config provides an inventory of your AWS resources and a history of configuration changes to these resources. You can use AWS Config to define rules that evaluate these configurations for compliance. Hence, it is important to enable this feature.",
    "Compliance": ["CSA-CCM","GDPR","HITRUST","ISO 27001","NIST 800","SOC 2"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
