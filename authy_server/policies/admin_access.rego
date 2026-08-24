package authz

default allow := false

allow {
    input.role == "admin"
    input.action == "read"
}

allow {
    input.role == "admin"
    input.action == "write"
}

allow {
    input.role == "admin"
    input.action == "delete"
}

allow {
    input.role == "admin"
    input.action == "manage_users"
}
