#
# PR-AWS-0060
#

package rule

default rulepass = true

# API Documentation: https://docs.aws.amazon.com/efs/latest/ug/API_DescribeFileSystems.html

rulepass = false {
    lower(resource.Type) == "aws::efs::filesystem"
    input.FileSystems[_].Encrypted == false
}

rulepass = false {
    lower(resource.Type) == "aws::efs::filesystem"
    fs := input.FileSystems[_]
    not startswith(fs.KmsKeyId, "arn:")
}
