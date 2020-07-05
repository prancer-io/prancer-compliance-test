package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html
# Id: 61

rulepass = false {
    input.FileSystems[_].Encrypted == false
}
