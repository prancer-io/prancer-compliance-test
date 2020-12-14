#
# PR-AWS-0022
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html

rulepass = true{
   input.Distribution.DistributionConfig.ViewerCertificate.CertificateSource!="cloudfront"
}
