from . import (
    __NEXT_OPERATION__,
    __FLOW_COMPLETE__,
    authentication_base,
    _auth_api_request,
    FORCE_PASSWORD_PROMPT,
)

AUTH_CLIENT_AUTH_REQUEST = "pam_auth_client_request"
AUTH_CLIENT_AUTH_RESPONSE = "pam_auth_response"
PERFORM_RUNNING = "running"
PERFORM_READY = "ready"
PERFORM_NEXT = "next"
PERFORM_RESPONSE = "response"
PERFORM_WAITING = "waiting"
PERFORM_WAITING_PW = "waiting_pw"
PERFORM_ERROR = "error"
PERFORM_TIMEOUT = "timeout"
PERFORM_AUTHENTICATED = "authenticated"
PERFORM_NOT_AUTHENTICATED = "not_authenticated"
PAM_INTERACTIVE_SCHEME = "pam_interactive"
PERFORM_NATIVE_AUTH = "native_auth"

AUTH_AGENT_AUTH_REQUEST = "auth_agent_auth_request"
AUTH_AGENT_AUTH_RESPONSE = "auth_agent_auth_response"

def login(conn, **extra_opt):
    auth_client_object = _pam_interactive_ClientAuthState(conn, scheme=PAM_INTERACTIVE_SCHEME)
    auth_client_object.authenticate_client(
        initial_request=extra_opt
    )

class _pam_interactive_ClientAuthState(authentication_base):
    def __init__(self, *_, **_kw):
        super().__init__(*_, **_kw)

    def auth_client_start(self, request):
        resp = request.copy()

        resp["pstate"] = resp.get("pstate", {})
        resp["pdirty"] = resp.get("pdirty", False)

        resp['user_name'] = self.conn.account.proxy_user
        resp['zone_name'] = self.conn.account.proxy_zone

        if not resp.get(FORCE_PASSWORD_PROMPT, False):
            if self.conn.account.password and self.conn.account.authentication_file_path:
                resp[__NEXT_OPERATION__] = PERFORM_NATIVE_AUTH
                return resp

        resp[__NEXT_OPERATION__] = AUTH_CLIENT_AUTH_REQUEST
        return resp

    def pam_auth_client_request(self, request):
        server_req = request.copy()
        server_req[__NEXT_OPERATION__] = AUTH_AGENT_AUTH_REQUEST

        resp = _auth_api_request(self.conn, server_req)
        resp[__NEXT_OPERATION__] = AUTH_CLIENT_AUTH_RESPONSE

        return resp