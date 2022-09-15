



# Master Test ID: PR-AZR-TRF-CDA-001


***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([databaseaccounts.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-TRF-CDA-001|
|eval|data.rule.tagsLength|
|message|data.rule.tagsLength_err|
|remediationDescription|In 'azurerm_cosmosdb_account' resource, add relevent tag on property 'tags' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account#tags' target='_blank'>here</a> for details.|
|remediationFunction|PR_AZR_TRF_CDA_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure that Cosmos DB Account has an associated tag

***<font color="white">Description:</font>*** Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['azurerm_cosmosdb_account']


[databaseaccounts.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/databaseaccounts.rego
