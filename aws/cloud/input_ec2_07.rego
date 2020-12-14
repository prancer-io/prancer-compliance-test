#
# PR-AWS-0045
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html

rulepass = false {
    instance := input.Reservations[_].Instances[_]
    not instance.VpcId
}
