package rule

firewall {
    resource = input.resources[_]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[_] != "0.0.0.0/0"
}

firewall = false {
    resource = input.resources[_]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[_] == "0.0.0.0/0"
}

firewall_err = "Firewall source port ranges allow access to all networks." {
    firewall == false
}
