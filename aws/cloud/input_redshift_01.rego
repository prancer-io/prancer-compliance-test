#
# PR-AWS-0137
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/redshift/latest/APIReference/API_DescribeClusters.html

rulepass = true {
    lower(resource.Type) == "aws::redshift::cluster"
    input.Clusters[_].Encrypted=true
}
