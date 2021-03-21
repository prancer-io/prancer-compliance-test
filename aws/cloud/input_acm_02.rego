#
# PR-AWS-0012
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html

rulepass = true {
    lower(input.Type) == "aws::certificatemanager::certificate"
    count(input.Certificate.InUseBy) > 0
}
