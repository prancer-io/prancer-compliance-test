package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html
# Id: 9

rulepass = true{
	input.Certificate.Options.CertificateTransparencyLoggingPreference="ENABLED"
}