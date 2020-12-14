#
# PR-AWS-0012
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html

rulepass = true{
	count(input.Certificate.InUseBy)>0
}
