package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html
# Id: 45

rulepass = false {
    instance := input.Reservations[_].Instances[_]
    not instance.VpcId
}
