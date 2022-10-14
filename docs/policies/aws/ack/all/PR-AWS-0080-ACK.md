



# Title: AWS Elasticsearch domain has Zone Awareness set to disabled


***<font color="white">Master Test Id:</font>*** TEST_ELASTIC_SEARCH_4

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0080-ACK|
|eval|data.rule.esearch_zone_awareness|
|message|data.rule.esearch_zone_awareness_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Elasticsearch domains for which Zone Awareness is disabled in your AWS account. Enabling Zone Awareness (cross-zone replication) increases the availability by distributing your Elasticsearch data nodes across two availability zones available in the same AWS region. It also prevents data loss and minimizes downtime in the event of node or availability zone failure.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/elasticsearch.rego
