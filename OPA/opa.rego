package barmanagement #namespace
import future.keywords
default allow := false

package http

import rego.v1

default allow := false

body := json.unmarshal(input.req_body)

token := split(body.input.request.headers.Authorization, " ")[1]

decoded := io.jwt.decode(token)

payload := decoded[1]

allow if {
    contains(body.input.request.path, "/api/bar")
    contains(body.input.request.method, "POST")
    contains(body.input.request.body.DrinkName, "Beer")
    "customer" in payload.role
    to_number(payload.age) >= 16
}

allow if {
    contains(body.input.request.path, "/api/bar")
    contains(body.input.request.method, "POST")
    # contains(body.input.request.body.DrinkName, "Fristi")
    "customer" in payload.role
 }

allow if {
    contains(body.input.request.path, "/api/managebar")
    contains(body.input.request.method, "POST")
    "bartender" in payload.role
}