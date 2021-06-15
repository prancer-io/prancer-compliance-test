#
# PR-AWS-0125
#

package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass {
    lower(input.Type) == "aws::rds::dbinstance"
    db_instance := input.DBInstances[_]
    db_instance.StorageEncrypted == true
}

metadata := {
    "Policy Code": "PR-AWS-0125",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS RDS instance is not encrypted",
    "Policy Description": "This policy identifies AWS RDS instances which are not encrypted. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to set up and manage databases. Amazon allows customers to turn on encryption for RDS which is recommended for compliance and security reasons.",
    "Compliance": ["CSA-CCM","GDPR","HIPAA","HITRUST","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html"
}

# If storage encryption is set to enabled then test will pass.
