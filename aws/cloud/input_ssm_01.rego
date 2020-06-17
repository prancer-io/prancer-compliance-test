package rule

default rulepass = false

# API: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeParameters.html
# Id: 158

rulepass = true{
    input.Parameters[_].Type='SecureString'
}
