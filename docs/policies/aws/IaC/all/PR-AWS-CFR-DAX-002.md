



# Title: Ensure AWS DAX data is encrypted in transit


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-DAX-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-DAX-002|
|eval|data.rule.dax_cluster_endpoint_encrypt_at_rest|
|message|data.rule.dax_cluster_endpoint_encrypt_at_rest_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html#cfn-dax-cluster-clusterendpointencryptiontype' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_DAX_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This control is to check that the communication between the application and DAX is always encrypted  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::dax::cluster']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
