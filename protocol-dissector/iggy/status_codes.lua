-- Status codes module for Iggy Protocol Dissector

local status_codes = {
    [0] = "OK",
    [1] = "Error",
    [2] = "InvalidConfiguration",
    [3] = "InvalidCommand",
    [40] = "Unauthenticated",
    [41] = "Unauthorized",
    [42] = "InvalidCredentials",
    [43] = "InvalidUsername",
    [44] = "InvalidPassword",
}

return status_codes
