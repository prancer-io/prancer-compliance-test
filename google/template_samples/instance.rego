package rule

instance {
    resource = input.resources[_]
    lower(resource.type) == "compute.v1.instance"
    resource.properties.zone
    resource.properties.zone != null
    resource.properties.zone != ""

    resource.properties.machineType
    resource.properties.machineType != null
    resource.properties.machineType != ""
}

instance = false {
    resource = input.resources[_]
    lower(resource.type) == "compute.v1.instance"
    not resource.properties.zone
    not resource.properties.machineType
}

instance_err = "zone or machine type does not set for instance" {
    instance == false
}
