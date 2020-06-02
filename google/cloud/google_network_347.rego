package rule
default rulepass = true

# GCP project is using the default network
# if GCP project is not using the default network 

# API and Response Reference : https://cloud.google.com/compute/docs/reference/rest/v1/networks/list

rulepass = false {                                      
   count(networksname) == 1
}

networksname[input.id] {
   input.name == "default"
}