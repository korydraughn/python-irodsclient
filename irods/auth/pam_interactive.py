from . import (
    __NEXT_OPERATION__,
    __FLOW_COMPLETE__,
    authentication_base,
    _auth_api_request,
    FORCE_PASSWORD_PROMPT,
    throw_if_request_message_is_missing_key,
    AuthStorage,
    STORE_PASSWORD_IN_MEMORY,
    CLIENT_GET_REQUEST_RESULT
)
from .native import _authenticate_native

import getpass
import sys

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
    depot = AuthStorage.create_temp_pw_storage(conn)

    auth_client_object = _pam_interactive_ClientAuthState(conn, depot, scheme=PAM_INTERACTIVE_SCHEME)
    auth_client_object.authenticate_client(
        initial_request=extra_opt
    )

class _pam_interactive_ClientAuthState(authentication_base):
    def __init__(self, conn, depot, *_, **_kw):
        super().__init__(conn, *_, **_kw)
        self.depot = depot
        self._list_for_request_result_return = None

    def auth_client_start(self, request):
        self._list_for_request_result_return = request.pop(CLIENT_GET_REQUEST_RESULT, None)

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

    def pam_auth_response(self, request):
        throw_if_request_message_is_missing_key(request, ["user_name", "zone_name"])

        server_req = request.copy()
        server_req[__NEXT_OPERATION__] = AUTH_AGENT_AUTH_RESPONSE

        resp = _auth_api_request(self.conn, server_req)

        return resp

    def _get_default_value(self, request):
        default_path = request.get("msg", {}).get("default_path", "")
        default_value = ""

        if default_path and default_path.startswith('/'):
            key = default_path[1:]
            pstate = request.get("pstate", {})

            if key in pstate:
                default_value = pstate[key]

        return default_value

    def _patch_state(self, req):
        patch_ops = req.get("msg", {}).get("patch")
        if not patch_ops:
            return

        pstate = req.get("pstate", {})
        resp = req.get("resp", "")

        for op in patch_ops:
            path = op.get("path", "")
            if not path.startswith('/'):
                continue

            key = path[1:]
            operation = op.get("op")

            value = op.get("value") if "value" in op else resp

            if operation == "add" or operation == "replace":
                pstate[key] = value
            elif operation == "remove":
                pstate.pop(key, None)

        req["pstate"] = pstate
        req["pdirty"] = True
        del req["msg"]["patch"]

    def _retrieve_entry(self, req):
        if "retrieve" not in req.get("msg", {}):
            return False

        retr_path = req["msg"].get("retrieve", "")
        if retr_path and retr_path.startswith('/'):
            key = retr_path[1:]
            pstate = req.get("pstate", {})
            if key in pstate:
                req["resp"] = pstate[key]
                return True

        req["resp"] = ""
        return True

    def waiting(self, request):
        server_req = request.copy()

        if self._retrieve_entry(server_req):
            self._patch_state(server_req)
            server_req[__NEXT_OPERATION__] = AUTH_AGENT_AUTH_RESPONSE
            return _auth_api_request(self.conn, server_req)

        prompt = server_req.get("msg", {}).get("prompt", "")
        default_value = self._get_default_value(server_req)

        display_prompt = f"{prompt} "
        if default_value:
            display_prompt = f"{prompt} [{default_value}] "

        sys.stdout.write(display_prompt)
        sys.stdout.flush()
        user_input = sys.stdin.readline().strip()

        if not user_input and default_value:
            server_req["resp"] = default_value
        else:
            server_req["resp"] = user_input

        self._patch_state(server_req)
        server_req[__NEXT_OPERATION__] = AUTH_AGENT_AUTH_RESPONSE

        return _auth_api_request(self.conn, server_req)

    def waiting_pw(self, request):
        server_req = request.copy()

        if self._retrieve_entry(server_req):
            self._patch_state(server_req)
            server_req[__NEXT_OPERATION__] = AUTH_AGENT_AUTH_RESPONSE
            return _auth_api_request(self.conn, server_req)

        prompt = server_req.get("msg", {}).get("prompt", "Password: ")
        default_value = self._get_default_value(server_req)

        display_prompt = prompt
        if default_value:
            display_prompt = f"{prompt} [******] "

        pw = getpass.getpass(display_prompt)

        if not pw and default_value:
            server_req["resp"] = default_value
        else:
            server_req["resp"] = pw

        self._patch_state(server_req)
        server_req[__NEXT_OPERATION__] = AUTH_AGENT_AUTH_RESPONSE

        return _auth_api_request(self.conn, server_req)

    def next(self, request):
        prompt = request.get("msg", {}).get("prompt", "")
        if prompt:
            print(prompt)

        server_req = request.copy()
        self._patch_state(server_req)
        server_req[__NEXT_OPERATION__] = AUTH_AGENT_AUTH_RESPONSE

        resp = _auth_api_request(self.conn, server_req)

        return resp

    def authenticated(self, request):
        throw_if_request_message_is_missing_key(request, ["request_result"])
        pw = request["request_result"]

        if not self.depot:
            raise RuntimeError("auth storage object was either not set, or allowed to expire prematurely.")

        if request.get(STORE_PASSWORD_IN_MEMORY):
            self.depot.use_client_auth_file(None)

        self.depot.store_pw(pw)

        if isinstance(self._list_for_request_result_return, list):
            self._list_for_request_result_return[:] = (pw,)

        resp = request.copy()
        resp[__NEXT_OPERATION__] = PERFORM_NATIVE_AUTH

        return resp

    def native_auth(self, request):
        resp = request.copy()

        _authenticate_native(self.conn, request)

        resp[__NEXT_OPERATION__] = __FLOW_COMPLETE__
        self.loggedIn = 1
        return resp
    def running(self, request):
        server_req = request.copy()
        self._patch_state(server_req)
        server_req[__NEXT_OPERATION__] = AUTH_AGENT_AUTH_RESPONSE

        resp = _auth_api_request(self.conn, server_req)

        return resp

    def ready(self, request):
        server_req = request.copy()
        self._patch_state(server_req)
        server_req[__NEXT_OPERATION__] = AUTH_AGENT_AUTH_RESPONSE

        resp = _auth_api_request(self.conn, server_req)

        return resp

    def response(self, request):
        server_req = request.copy()
        self._patch_state(server_req)
        server_req[__NEXT_OPERATION__] = AUTH_AGENT_AUTH_RESPONSE

        resp = _auth_api_request(self.conn, server_req)

        return resp

    def error(self, request):
        print("Authentication error.")
        resp = request.copy()
        resp[__NEXT_OPERATION__] = __FLOW_COMPLETE__
        self.loggedIn = 0
        return resp

    def timeout(self, request):
        print("Authentication timed out.")
        resp = request.copy()
        resp[__NEXT_OPERATION__] = __FLOW_COMPLETE__
        self.loggedIn = 0
        return resp

    def not_authenticated(self, request):
        print("Authentication failed.")
        resp = request.copy()
        resp[__NEXT_OPERATION__] = __FLOW_COMPLETE__
        self.loggedIn = 0
        return resp