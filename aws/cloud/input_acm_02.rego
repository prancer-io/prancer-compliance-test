package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html
# Id: 12

rulepass = true{
	count(input.Certificate.InUseBy)>0
}
