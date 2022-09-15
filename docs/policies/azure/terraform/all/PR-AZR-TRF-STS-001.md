



# Master Test ID: PR-AZR-TRF-STS-001


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage_sync.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-STS-001|
|eval|data.rule.storage_sync_public_network_access_disabled|
|message|data.rule.storage_sync_public_network_access_disabled_err|
|remediationDescription|In 'azurerm_storage_sync' resource, set incoming_traffic_policy = 'AllowVirtualNetworksOnly' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_sync#incoming_traffic_policy' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_STS_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Public network access should be disabled for Azure File Sync

***<font color="white">Description:</font>*** Disabling the public endpoint allows you to restrict access to your Storage Sync Service resource to requests destined to approved private endpoints on your organization's network. There is nothing inherently insecure about allowing requests to the public endpoint, however, you may wish to disable it to meet regulatory, legal, or organizational policy requirements. You can disable the public endpoint for a Storage Sync Service by setting the incomingTrafficPolicy of the resource to AllowVirtualNetworksOnly.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_storage_sync']


[storage_sync.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storage_sync.rego
