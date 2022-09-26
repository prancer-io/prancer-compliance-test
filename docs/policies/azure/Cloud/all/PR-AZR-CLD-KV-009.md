



# Title: Configure Azure Key Vaults with private endpoints


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-KV-009

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_228', 'AZRSNP_500']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([Keyvault.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-KV-009|
|eval|data.rule.kv_private_endpoint|
|message|data.rule.kv_private_endpoint_err|
|remediationDescription|Follow the guideline mentioned <a href='https://docs.microsoft.com/en-us/azure/key-vault/general/private-link-service?tabs=portal' target='_blank'>here</a>|
|remediationFunction|PR_AZR_CLD_KV_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your key vault, data leakage risks are reduced. Learn more about private links at - https://aka.ms/azureprivatelinkoverview  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Security']|



[Keyvault.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/Keyvault.rego
