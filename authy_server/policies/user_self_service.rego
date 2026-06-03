package authz

default allow := false

# Users can read their own data
allow {
    input.role == "user"
    input.action == "read"
    input.resource_owner == input.user_id
}

# Users can update their own profile
allow {
    input.role == "user"
    input.action == "update_profile"
    input.resource_owner == input.user_id
}

# Users cannot delete accounts without MFA
allow {
    input.role == "user"
    input.action == "delete_account"
    input.resource_owner == input.user_id
    input.mfa_verified == true
}
