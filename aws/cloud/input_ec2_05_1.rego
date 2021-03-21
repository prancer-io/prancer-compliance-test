#
# PR-AWS-0042
#

package rule

default rulepass = false

# API Documentation: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html
# Id: 42

rulepass {
    lower(input.Type) == "aws::ec2::instance"
    instance := input.Reservations[_].Instances[_]
    instance.IamInstanceProfile.Arn
}

# The condition instance.IamInstanceProfile.Arn will be true, if the value exists in the ec2 collection created. 
# Therefore the test case will pass.
