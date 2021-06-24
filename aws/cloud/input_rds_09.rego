#
# PR-AWS-0131
#

package rule

default rulepass = true

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

rulepass = false {
    # lower(input.json.Type) == "aws::rds::dbinstance"
    db_instance := input.json.DBInstances[_]
    to_number(db_instance.BackupRetentionPeriod) < 7
}

metadata := {
    "Policy Code": "PR-AWS-0131",
    "Type": "Cloud",
    "Product": "AWS",
    "Language": "Cloud",
    "Policy Title": "AWS RDS retention policy less than 7 days",
    "Policy Description": "RDS Retention Policies for Backups are an important part of your DR/BCP strategy. Recovering data from catastrophic failures, malicious attacks, or corruption often requires a several day window of potentially good backup material to leverage. As such, the best practice is to ensure your RDS clusters are retaining at least 7 days of backups, if not more (up to a maximum of 35).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html"
}
