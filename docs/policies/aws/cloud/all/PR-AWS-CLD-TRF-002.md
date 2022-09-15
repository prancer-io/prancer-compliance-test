



# Master Test ID: PR-AWS-CLD-TRF-002


***<font color="white">Master Snapshot Id:</font>*** ['TEST_TRF']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-TRF-002|
|eval|data.rule.transfer_server_protocol|
|message|data.rule.transfer_server_protocol_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/transfer.html#Transfer.Client.describe_server' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_TRF_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure Transfer Server is not use FTP protocol.

***<font color="white">Description:</font>*** It checks if FTP protocol is not used for AWS Transfer Family server.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['Best Practice']|
|service|['transfer']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
