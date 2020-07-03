package rule

default rulepass = false

# API: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusters.html
# Id: 119

rulepass {
   db_cluster := input.DBClusters[_]
   db_cluster.StorageEncrypted == true
}
