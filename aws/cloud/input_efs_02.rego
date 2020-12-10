#
# PR-AWS-0060
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html

rulepass = false {
    input.FileSystems[_].Encrypted == false
}

rulepass = false {
    fs := input.FileSystems[_]
    not startswith(fs.KmsKeyId, "arn:")
}
