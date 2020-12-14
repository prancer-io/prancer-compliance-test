#
# PR-AWS-0009
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html

rulepass = true{
	input.Certificate.Options.CertificateTransparencyLoggingPreference="ENABLED"
}