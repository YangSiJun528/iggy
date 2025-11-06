-- Constants module for Iggy Protocol Dissector

local constants = {}

----------------------------------------
-- Protocol constants
----------------------------------------
constants.IGGY_MIN_HEADER_LEN = 8  -- Minimum: LENGTH(4) + CODE/STATUS(4)

----------------------------------------
-- Status code mappings
----------------------------------------
constants.status_codes = {
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

return constants
