



# Master Test ID: PR-AWS-CLD-ES-007


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ELASTICSEARCH']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elasticsearch.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ES-007|
|eval|data.rule.esearch_node_encryption|
|message|data.rule.esearch_node_encryption_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-nodetonodeencryptionoptions' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ES_007.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure node-to-node encryption is enabled on each ElasticSearch Domain

***<font color="white">Description:</font>*** Ensure that node-to-node encryption feature is enabled for your AWS ElasticSearch domains (clusters) in order to add an extra layer of data protection on top of the existing ES security features such as HTTPS client to cluster encryption and data-at-rest encryption, and meet strict compliance requirements. The ElasticSearch node-to-node encryption capability provides the additional layer of security by implementing Transport Layer Security (TLS) for all communications between the nodes provisioned within the cluster. The feature ensures that any data sent to your AWS ElasticSearch domain over HTTPS remains encrypted in transit while it is being distributed and replicated between the nodes.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['CSA CCM', 'NIST 800']|
|service|['elasticsearch']|



[elasticsearch.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/elasticsearch.rego
