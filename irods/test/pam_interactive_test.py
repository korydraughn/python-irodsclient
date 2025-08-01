
import unittest
import os
import json
from irods.client_init import write_pam_interactive_irodsA_file
from unittest.mock import patch
from irods.auth import ClientAuthError, FORCE_PASSWORD_PROMPT
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
        if os.path.exists(self.auth_file_path):
            os.remove(self.auth_file_path)

    def test_pam_interactive_login_basic(self):
        with patch("getpass.getpass", return_value=self.password):
            self.sess = make_session(test_server_version=False, env_file=self.env_file_path, authentication_scheme="pam_interactive")
            self.assertTrue(self.sess.server_version)
            self.assertEqual(self.sess.username, self.user)
            self.assertEqual(self.sess.zone, self.zone)

    def test_pam_interactive_auth_file_creation(self):
        with patch("getpass.getpass", return_value=self.password):
            write_pam_interactive_irodsA_file(env_file=self.env_file_path)
            self.assertTrue(os.path.exists(self.auth_file_path), ".irodsA file was not created")

        with patch("getpass.getpass", return_value=self.password) as mock_getpass:
            self.sess = make_session(test_server_version=False, env_file=self.env_file_path, authentication_scheme= "pam_interactive")
            self.assertTrue(self.sess.server_version)
            self.assertEqual(self.sess.username, self.user)
            self.assertEqual(self.sess.zone, self.zone)
            mock_getpass.assert_not_called()

    def test_forced_interactive_flow(self):
        with patch("getpass.getpass", return_value=self.password):
            write_pam_interactive_irodsA_file(env_file=self.env_file_path)
            self.assertTrue(os.path.exists(self.auth_file_path), ".irodsA file was not created")

        with patch("getpass.getpass", return_value=self.password) as mock_getpass:
            self.sess = make_session(test_server_version=False, env_file=self.env_file_path, authentication_scheme="pam_interactive")
            self.sess.set_auth_option_for_scheme("pam_interactive", FORCE_PASSWORD_PROMPT, True)
            self.assertTrue(self.sess.server_version)
            self.assertEqual(self.sess.username, self.user)
            self.assertEqual(self.sess.zone, self.zone)
            mock_getpass.assert_called_once()

    def test_failed_login_incorrect_password(self):
        with patch("getpass.getpass", return_value="wrong_password"):
            with self.assertRaises(ClientAuthError):
                self.sess = make_session(test_server_version=False, env_file=self.env_file_path, authentication_scheme="pam_interactive")
                _ = self.sess.server_version # trigger auth flow

        with patch("getpass.getpass", return_value="wrong_password"):
            with self.assertRaises(ClientAuthError):
                write_pam_interactive_irodsA_file(env_file=self.env_file_path)

if __name__ == "__main__":
    unittest.main()