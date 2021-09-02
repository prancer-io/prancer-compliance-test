package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationrecorder.html

# #
# # PR-AWS-0031-CFR
# #

# default config_recorder = null

# aws_issue["config_recorder"] {
#     resource := input.Resources[i]
#     lower(resource.Type) == "aws::config::configurationrecorder"
#     not resource.Properties.RecordingGroup
# }

# aws_issue["config_recorder"] {
#     resource := input.Resources[i]
#     lower(resource.Type) == "aws::config::configurationrecorder"
#     resource.Properties.RecordingGroup
#     lower(resource.Properties.RecordingGroup.AllSupported) == "false"
#     count(resource.Properties.RecordingGroup.ResourceTypes) == 0
# }

# aws_bool_issue["config_recorder"] {
#     resource := input.Resources[i]
#     lower(resource.Type) == "aws::config::configurationrecorder"
#     resource.Properties.RecordingGroup
#     not resource.Properties.RecordingGroup.AllSupported
#     count(resource.Properties.RecordingGroup.ResourceTypes) == 0
# }

# config_recorder {
#     lower(input.Resources[i].Type) == "aws::config::configurationrecorder"
#     not aws_issue["config_recorder"]
#     not aws_bool_issue["config_recorder"]
# }

# config_recorder = false {
#     aws_issue["config_recorder"]
# }

# config_recorder = false {
#     aws_bool_issue["config_recorder"]
# }

# config_recorder_err = "AWS Config Recording is disabled" {
#     aws_issue["config_recorder"]
# } else = "AWS Config Recording is disabled" {
#     aws_bool_issue["config_recorder"]
# }

# config_recorder_metadata := {
#     "Policy Code": "PR-AWS-0031-CFR",
#     "Type": "IaC",
#     "Product": "AWS",
#     "Language": "AWS Cloud formation",
#     "Policy Title": "AWS Config Recording is disabled",
#     "Policy Description": "AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. AWS config uses configuration recorder to detect changes in your resource configurations and capture these changes as configuration items. It continuously monitors and records your AWS resource configurations and allows you to automate the evaluation of recorded configurations against desired configurations. This policy generates alerts when AWS Config recorder is not enabled.",
#     "Resource Type": "",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationrecorder.html"
# }


#
# PR-AWS-0033-CFR
#

default config_all_resource = null

aws_issue["config_all_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    not resource.Properties.RecordingGroup
}

aws_issue["config_all_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    lower(resource.Properties.RecordingGroup.AllSupported) == "false"
}

aws_issue["config_all_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    lower(resource.Properties.RecordingGroup.IncludeGlobalResourceTypes) == "false"
}

aws_bool_issue["config_all_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    not resource.Properties.RecordingGroup.AllSupported
}

aws_bool_issue["config_all_resource"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::config::configurationrecorder"
    resource.Properties.RecordingGroup
    not resource.Properties.RecordingGroup.IncludeGlobalResourceTypes
}


config_all_resource {
    lower(input.Resources[i].Type) == "aws::config::configurationrecorder"
    not aws_issue["config_all_resource"]
    not aws_bool_issue["config_all_resource"]
}

config_all_resource = false {
    aws_issue["config_all_resource"]
}

config_all_resource = false {
    aws_bool_issue["config_all_resource"]
}

config_all_resource_err = "AWS Config must record all possible resources" {
    aws_issue["config_all_resource"]
} else = "AWS Config must record all possible resources" {
    aws_bool_issue["config_all_resource"]
}

config_all_resource_metadata := {
    "Policy Code": "PR-AWS-0033-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Config must record all possible resources",
    "Policy Description": "This policy identifies resources for which AWS Config recording is enabled but recording for all possible resources are disabled. AWS Config provides an inventory of your AWS resources and a history of configuration changes to these resources. You can use AWS Config to define rules that evaluate these configurations for compliance. Hence, it is important to enable this feature.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationrecorder.html"
}

