package rule

default rulepass = false

# API: https://docs.aws.amazon.com/redshift/latest/APIReference/API_DescribeClusters.html
# ID: 137

rulepass = true{
   input.Clusters[_].Encrypted=true
}
