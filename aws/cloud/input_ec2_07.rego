#
# PR-AWS-0045
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html

rulepass = false {
    lower(input.Type) == "aws::ec2::instance"
    instance := input.Reservations[_].Instances[_]
    not instance.VpcId
}

metadata := {
    "Policy Code": "PR-AWS-0045",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS EC2 instance is not configured with VPC",
    "Policy Description": "This policy identifies the EC2 instances which are still using EC2 Classic. There are no VPCs deployed any EC2 instances will be running on AWS EC2 Classic. Deploying VPCs will enable you to leverage enhanced infrastructure security controls._x005F_x000D_ Note: This alert only triggers in regions that support launching into AWS Classic.",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html"
}
