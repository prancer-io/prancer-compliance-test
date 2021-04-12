#
# PR-AWS-0009
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html

rulepass = true {
    lower(input.Type) == "aws::certificatemanager::certificate"
    input.Certificate.Options.CertificateTransparencyLoggingPreference="ENABLED"
}