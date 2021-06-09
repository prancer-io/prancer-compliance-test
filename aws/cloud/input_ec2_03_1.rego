#
# PR-AWS-0038
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html

rulepass = true {
    lower(input.Type) == "AWS::EC2::Volume"
    input.Volumes[_].Attachments[_].State="attached"
}

rulepass = true {
    lower(input.Type) == "AWS::EC2::Volume"
    input.Volumes[_].Attachments[_]
}

metadata := {
    "Policy Code": "PR-AWS-0038",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS EBS Volume is unattached",
    "Policy Description": "EBS volumes often persist after an EC2 instance has been terminated. We recommend regular review of these volumes, since they can contain sensitive data related to your company, application, infrastructure, or even users.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html"
}

# The value for the key input.Volumes[_].Attachments[_].State is equal to "attached" and the attachment list is not null. As both
# the above conditions are True. Therefore the test will pass.
