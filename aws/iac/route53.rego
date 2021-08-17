package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-healthcheck.html

#
# PR-AWS-0245-CFR
#

default route_healthcheck_disable = null

aws_issue["route_healthcheck_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "AWS::Route53::RecordSetGroup"
    lower(resource.Properties.AliasTarget.EvaluateTargetHealth) == "false"
}

aws_bool_issue["route_healthcheck_disable"] {
    resource := input.Resources[i]
    lower(resource.Type) == "AWS::Route53::RecordSetGroup"
    not resource.Properties.AliasTarget.EvaluateTargetHealth
}

route_healthcheck_disable {
    lower(input.Resources[i].Type) == "AWS::Route53::RecordSetGroup"
    not aws_issue["route_healthcheck_disable"]
    not aws_bool_issue["route_healthcheck_disable"]
}

route_healthcheck_disable = false {
    aws_issue["route_healthcheck_disable"]
}

route_healthcheck_disable = false {
    aws_bool_issue["route_healthcheck_disable"]
}

route_healthcheck_disable_err = "Ensure Route53 DNS evaluateTargetHealth is enabled" {
    aws_issue["route_healthcheck_disable"]
} else = "Ensure Route53 DNS evaluateTargetHealth is enabled" {
    aws_bool_issue["route_healthcheck_disable"]
}

route_healthcheck_disable_metadata := {
    "Policy Code": "PR-AWS-0245-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Route53 DNS evaluateTargetHealth is enabled",
    "Policy Description": "The EvaluateTargetHealth of Route53 is not enabled, an alias record can't inherits the health of the referenced AWS resource, such as an ELB load balancer or another record in the hosted zone.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbcluster.html"
}