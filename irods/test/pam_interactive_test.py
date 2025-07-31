
import unittest
import os
import json
from irods.client_init import write_pam_interactive_irodsA_file
from unittest.mock import patch
from irods.auth import ClientAuthError
from irods.auth.pam_interactive import (
    _pam_interactive_ClientAuthState,
    PERFORM_WAITING,
    PERFORM_WAITING_PW,
    PERFORM_AUTHENTICATED,
)
from irods.test.helpers import make_session

class PamInteractiveTest(unittest.TestCase):

    def setUp(self):
        self.sess = None
        self.env_file_path = os.path.expanduser("~/.irods/irods_environment.json")
        self.auth_file_path = os.path.expanduser("~/.irods/.irodsA")

        with open(self.env_file_path) as f:
            env = json.load(f)
        self.user = env.get("irods_user_name", "alice")
        self.zone = env.get("irods_zone_name", "tempZone")
        self.password = "rods"

    def tearDown(self):
        if self.sess:
            self.sess.cleanup()

if __name__ == "__main__":
    unittest.main()