package authz

default allow := false

# Business hours access (9 AM - 6 PM UTC)
allow {
    input.hour >= 9
    input.hour < 18
    input.day_of_week < 5  # Monday-Friday
    input.role in ["employee", "admin"]
}

# Emergency access always allowed for admins
allow {
    input.role == "admin"
    input.emergency == true
}
