package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig.html
#
# PR-AWS-0256-CFR
#

default as_volume_encrypted = null

aws_issue["as_volume_encrypted"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    count([c | resource.Properties.BlockDeviceMappings; c:=1]) == 0
}

aws_bool_issue["as_volume_encrypted"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    bdm := resource.Properties.BlockDeviceMappings[_]
    not bdm.Ebs.Encrypted
}

aws_issue["as_volume_encrypted"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::launchconfiguration"
    bdm := resource.Properties.BlockDeviceMappings[_]
    lower(bdm.Ebs.Encrypted) != "true"
}


as_volume_encrypted {
    lower(input.Resources[i].Type) == "aws::autoscaling::launchconfiguration"
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
    "Policy Code": "PR-AWS-0256-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure EBS volumes have encrypted launch configurations",
    "Policy Description": "Amazon Elastic Block Store (EBS) volumes allow you to create encrypted launch configurations when creating EC2 instances and auto scaling. When the entire EBS volume is encrypted, data stored at rest on the volume, disk I/O, snapshots created from the volume, and data in-transit between EBS and EC2 are all encrypted.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig-blockdev-template.html#cfn-as-launchconfig-blockdev-template-encrypted"
}

#
# PR-AWS-0347-CFR
#

default as_elb_health_check = null

aws_issue["as_elb_health_check"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    resource.Properties.LoadBalancerNames
    lower(resource.Properties.HealthCheckType) != "elb"
}

aws_issue["as_elb_health_check"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::autoscaling::autoscalinggroup"
    resource.Properties.TargetGroupARNs
    lower(resource.Properties.HealthCheckType) != "elb"
}

as_elb_health_check {
    lower(input.Resources[i].Type) == "aws::autoscaling::autoscalinggroup"
    not aws_issue["as_elb_health_check"]
}

as_elb_health_check = false {
    aws_issue["as_elb_health_check"]
}

as_elb_health_check_err = "Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks" {
    aws_issue["as_elb_health_check"]
}

as_elb_health_check_metadata := {
    "Policy Code": "PR-AWS-0347-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks",
    "Policy Description": "If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-healthchecktype"
}