package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig.html
#
# PR-AWS-0256-TRF
#

default as_volume_encrypted = null

aws_issue["as_volume_encrypted"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    count([c | resource.properties.ebs_block_device; c:=1]) == 0
}

aws_bool_issue["as_volume_encrypted"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    ebs_block_device := resource.properties.ebs_block_device[_]
    not ebs_block_device.encrypted
}

aws_issue["as_volume_encrypted"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_launch_configuration"
    ebs_block_device := resource.properties.ebs_block_device[_]
    lower(ebs_block_device.encrypted) != "true"
}


as_volume_encrypted {
    lower(input.resources[i].type) == "aws_launch_configuration"
    not aws_issue["as_volume_encrypted"]
    not aws_bool_issue["as_volume_encrypted"]
}

as_volume_encrypted = false {
    aws_issue["as_volume_encrypted"]
}

as_volume_encrypted = false {
    aws_bool_issue["as_volume_encrypted"]
}

as_volume_encrypted_err = "Ensure EBS volumes have encrypted launch configurations" {
    aws_issue["as_volume_encrypted"]
} else = "Ensure EBS volumes have encrypted launch configurations" {
    aws_bool_issue["as_volume_encrypted"]
}

as_volume_encrypted_metadata := {
    "Policy Code": "PR-AWS-0256-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EBS volumes have encrypted launch configurations",
    "Policy Description": "Amazon Elastic Block Store (EBS) volumes allow you to create encrypted launch configurations when creating EC2 instances and auto scaling. When the entire EBS volume is encrypted, data stored at rest on the volume, disk I/O, snapshots created from the volume, and data in-transit between EBS and EC2 are all encrypted.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig-blockdev-template.html#cfn-as-launchconfig-blockdev-template-encrypted"
}