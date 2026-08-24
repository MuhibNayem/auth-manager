package authz

default allow := false

# Public data - anyone can read
allow {
    input.data_classification == "public"
    input.action == "read"
}

# Internal data - employees only
allow {
    input.data_classification == "internal"
    input.action == "read"
    input.employee == true
}

# Confidential data - requires specific clearance
allow {
    input.data_classification == "confidential"
    input.action == "read"
    input.clearance_level >= 3
}

# Restricted data - admin only with audit
allow {
    input.data_classification == "restricted"
    input.action == "read"
    input.role == "admin"
    input.audit_enabled == true
}
