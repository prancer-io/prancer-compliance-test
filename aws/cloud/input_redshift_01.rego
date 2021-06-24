#
# PR-AWS-0137
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/redshift/latest/APIReference/API_DescribeClusters.html

rulepass = true {
    # lower(input.Type) == "aws::redshift::cluster"
    input.Clusters[_].Encrypted=true
}

metadata := {
    "Policy Code": "PR-AWS-0137",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Redshift instances are not encrypted",
    "Policy Description": "This policy identifies AWS Redshift instances which are not encrypted. These instances should be encrypted for clusters to help protect data at rest which otherwise can result in a data breach.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/redshift/latest/APIReference/API_DescribeClusters.html"
}
