#
# PR-AWS-0012
#

package rule

default rulepass = false

# API Reference : https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html

rulepass = true {
    # lower(input.Type) == "aws::certificatemanager::certificate"
    count(input.Certificate.InUseBy) > 0
}

metadata := {
    "Policy Code": "PR-AWS-0012",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS Certificate Manager (ACM) has unused certificates",
    "Policy Description": "This policy identifies unused certificates which are in AWS Certificate Manager. AWS Certificate Manager (ACM) is the preferred tool to provision, manage, and deploy your server certificates. With ACM you can request a certificate or deploy an existing ACM or external certificate to AWS resources. This policy generates alerts if there are any unused ACM managed certificates. As a best practice, it is recommended to delete unused certificates or associate those certificates with any resources.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html"
}
