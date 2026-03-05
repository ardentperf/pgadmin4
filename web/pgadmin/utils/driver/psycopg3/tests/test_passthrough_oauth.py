##########################################################################
#
# pgAdmin 4 - PostgreSQL Tools
#
# Copyright (C) 2013 - 2026, The pgAdmin Development Team
# This software is released under the PostgreSQL Licence
#
##########################################################################

"""
Tests for the OAuth passthrough identity feature.

This feature allows pgAdmin to connect to PostgreSQL using a system-configured
client certificate, authenticating as the currently logged-in OAuth2 user.
The certificate is a privileged proxy credential; these tests verify it can
never be used without a valid OAuth2-authenticated user in scope.

Two test classes:

  TestPassthroughGates
      Tests the _check_passthrough_oauth() gate function in isolation.
      Each security gate must raise an Exception with a descriptive message;
      no gate may silently fall through or substitute a stored username.

  TestPassthroughConnectionString
      Tests ServerManager.create_connection_string() with the new strip_keys
      and inject_params parameters that the passthrough branch uses.
      Covers: username substitution, cert injection, sslcert/sslkey stripping
      from connection_params, no-password guarantee, and preservation of other
      connection params. Also includes regression tests for normal (non-
      passthrough) mode to confirm existing behaviour is unchanged.
"""

from unittest.mock import patch, MagicMock

from pgadmin.utils.route import BaseTestGenerator


# ---------------------------------------------------------------------------
# Security gate tests
# ---------------------------------------------------------------------------

class TestPassthroughGates(BaseTestGenerator):
    """
    Verify that _check_passthrough_oauth() raises a descriptive Exception for
    every failure condition.  Each scenario configures one failing gate; the
    test asserts that the exception message contains a meaningful fragment so
    that operators can diagnose misconfiguration.
    """

    scenarios = [
        # Gate 1a: OAUTH_PASSTHROUGH_SSL_CERT missing from config entirely
        ('passthrough_no_cert_config', dict(
            app_config={},
            user_auth_source='oauth2',
            user_is_authenticated=True,
            expected_fragment='OAUTH_PASSTHROUGH_SSL_CERT',
        )),

        # Gate 1b: OAUTH_PASSTHROUGH_SSL_KEY missing from config
        ('passthrough_no_key_config', dict(
            app_config={'OAUTH_PASSTHROUGH_SSL_CERT': '/etc/pgadmin/c.crt'},
            user_auth_source='oauth2',
            user_is_authenticated=True,
            expected_fragment='OAUTH_PASSTHROUGH_SSL_KEY',
        )),

        # Gate 2: user is not authenticated at all
        ('passthrough_not_authenticated', dict(
            app_config={
                'OAUTH_PASSTHROUGH_SSL_CERT': '/etc/pgadmin/c.crt',
                'OAUTH_PASSTHROUGH_SSL_KEY': '/etc/pgadmin/c.key',
            },
            user_auth_source='oauth2',
            user_is_authenticated=False,
            expected_fragment='authenticated',
        )),

        # Gate 3a: user authenticated via internal password
        ('passthrough_auth_internal', dict(
            app_config={
                'OAUTH_PASSTHROUGH_SSL_CERT': '/etc/pgadmin/c.crt',
                'OAUTH_PASSTHROUGH_SSL_KEY': '/etc/pgadmin/c.key',
            },
            user_auth_source='internal',
            user_is_authenticated=True,
            expected_fragment='OAuth2',
        )),

        # Gate 3b: user authenticated via LDAP
        ('passthrough_auth_ldap', dict(
            app_config={
                'OAUTH_PASSTHROUGH_SSL_CERT': '/etc/pgadmin/c.crt',
                'OAUTH_PASSTHROUGH_SSL_KEY': '/etc/pgadmin/c.key',
            },
            user_auth_source='ldap',
            user_is_authenticated=True,
            expected_fragment='OAuth2',
        )),

        # Gate 3c: user authenticated via Kerberos
        ('passthrough_auth_kerberos', dict(
            app_config={
                'OAUTH_PASSTHROUGH_SSL_CERT': '/etc/pgadmin/c.crt',
                'OAUTH_PASSTHROUGH_SSL_KEY': '/etc/pgadmin/c.key',
            },
            user_auth_source='kerberos',
            user_is_authenticated=True,
            expected_fragment='OAuth2',
        )),

        # Gate 3d: user authenticated via webserver header
        ('passthrough_auth_webserver', dict(
            app_config={
                'OAUTH_PASSTHROUGH_SSL_CERT': '/etc/pgadmin/c.crt',
                'OAUTH_PASSTHROUGH_SSL_KEY': '/etc/pgadmin/c.key',
            },
            user_auth_source='webserver',
            user_is_authenticated=True,
            expected_fragment='OAuth2',
        )),
    ]

    def runTest(self):
        from pgadmin.utils.driver.psycopg3.connection import \
            _check_passthrough_oauth

        manager = MagicMock()
        manager.passthrough_oauth_identity = True

        with self.app.app_context():
            with patch(
                'pgadmin.utils.driver.psycopg3.connection.current_user'
            ) as mock_user, patch(
                'pgadmin.utils.driver.psycopg3.connection.current_app'
            ) as mock_app:
                mock_user.is_authenticated = self.user_is_authenticated
                mock_user.auth_source = self.user_auth_source
                mock_app.config = self.app_config

                with self.assertRaises(Exception) as ctx:
                    _check_passthrough_oauth(manager)

                self.assertIn(
                    self.expected_fragment,
                    str(ctx.exception),
                    msg=(
                        f"Exception for scenario '{self.scenario_name}' "
                        f"should mention '{self.expected_fragment}', got: "
                        f"{ctx.exception}"
                    )
                )



# ---------------------------------------------------------------------------
# Connection string correctness tests
# ---------------------------------------------------------------------------

class TestPassthroughConnectionString(BaseTestGenerator):
    """
    Verify ServerManager.create_connection_string() behaviour with the new
    strip_keys and inject_params parameters used in passthrough mode.

    Tests call create_connection_string() as an unbound method with a minimal
    mock 'self', avoiding the need for a real database or running server.
    The result is parsed back via psycopg.conninfo.conninfo_to_dict so
    assertions are on actual libpq parameter values, not string fragments.
    """

    # Shared config for the passing gate scenarios
    _CERT = '/etc/pgadmin/passthrough.crt'
    _KEY = '/etc/pgadmin/passthrough.key'

    scenarios = [
        # 1. username comes from current_user, not from manager.user
        ('passthrough_uses_oauth_username', dict(
            connection_params={},
            strip_keys={'sslcert', 'sslkey'},
            inject_params={
                'sslcert': '/etc/pgadmin/passthrough.crt',
                'sslkey': '/etc/pgadmin/passthrough.key',
            },
            call_user='alice',       # simulates current_user.username
            call_password=None,
            assert_user='alice',
            assert_not_user='postgres',  # manager.user — must NOT appear
            assert_has_keys={'sslcert', 'sslkey'},
            assert_missing_keys={'password'},
            assert_sslcert='/etc/pgadmin/passthrough.crt',
            assert_sslkey='/etc/pgadmin/passthrough.key',
            assert_preserved_params={},
        )),

        # 2. system cert/key from config replaces anything in connection_params
        ('passthrough_uses_config_cert', dict(
            connection_params={
                'sslcert': '/home/user/client.crt',
                'sslkey': '/home/user/client.key',
            },
            strip_keys={'sslcert', 'sslkey'},
            inject_params={
                'sslcert': '/etc/pgadmin/passthrough.crt',
                'sslkey': '/etc/pgadmin/passthrough.key',
            },
            call_user='alice',
            call_password=None,
            assert_user='alice',
            assert_not_user=None,
            assert_has_keys={'sslcert', 'sslkey'},
            assert_missing_keys={'password'},
            assert_sslcert='/etc/pgadmin/passthrough.crt',
            assert_sslkey='/etc/pgadmin/passthrough.key',
            assert_preserved_params={},
        )),

        # 3. sslcert and sslkey from connection_params are stripped; config
        #    paths from inject_params take their place
        ('passthrough_strips_conn_params_cert', dict(
            connection_params={
                'sslcert': '/home/user/client.crt',
                'sslkey': '/home/user/client.key',
                'sslmode': 'verify-full',
            },
            strip_keys={'sslcert', 'sslkey'},
            inject_params={
                'sslcert': '/etc/pgadmin/passthrough.crt',
                'sslkey': '/etc/pgadmin/passthrough.key',
            },
            call_user='alice',
            call_password=None,
            assert_user='alice',
            assert_not_user=None,
            assert_has_keys={'sslcert', 'sslkey'},
            assert_missing_keys={'password'},
            assert_sslcert='/etc/pgadmin/passthrough.crt',
            assert_sslkey='/etc/pgadmin/passthrough.key',
            assert_preserved_params={'sslmode': 'verify-full'},
        )),

        # 4. no password appears in the DSN in passthrough mode
        ('passthrough_no_password_in_dsn', dict(
            connection_params={},
            strip_keys={'sslcert', 'sslkey'},
            inject_params={
                'sslcert': '/etc/pgadmin/passthrough.crt',
                'sslkey': '/etc/pgadmin/passthrough.key',
            },
            call_user='alice',
            call_password=None,
            assert_user='alice',
            assert_not_user=None,
            assert_has_keys={'sslcert', 'sslkey'},
            assert_missing_keys={'password'},
            assert_sslcert='/etc/pgadmin/passthrough.crt',
            assert_sslkey='/etc/pgadmin/passthrough.key',
            assert_preserved_params={},
        )),

        # 5. other connection_params (sslmode, application_name) are preserved
        ('passthrough_preserves_other_params', dict(
            connection_params={
                'sslcert': '/home/user/client.crt',
                'sslkey': '/home/user/client.key',
                'sslmode': 'verify-full',
                'application_name': 'my_app',
            },
            strip_keys={'sslcert', 'sslkey'},
            inject_params={
                'sslcert': '/etc/pgadmin/passthrough.crt',
                'sslkey': '/etc/pgadmin/passthrough.key',
            },
            call_user='bob',
            call_password=None,
            assert_user='bob',
            assert_not_user=None,
            assert_has_keys={'sslcert', 'sslkey'},
            assert_missing_keys={'password'},
            assert_sslcert='/etc/pgadmin/passthrough.crt',
            assert_sslkey='/etc/pgadmin/passthrough.key',
            assert_preserved_params={
                'sslmode': 'verify-full',
                'application_name': 'my_app',
            },
        )),

        # 6. Regression: normal mode uses the stored manager.user, not
        #    current_user.username.  No strip_keys or inject_params.
        ('normal_mode_uses_manager_user', dict(
            connection_params={},
            strip_keys=None,
            inject_params=None,
            call_user='postgres',   # this is manager.user in normal mode
            call_password=None,
            assert_user='postgres',
            assert_not_user=None,
            assert_has_keys=set(),
            assert_missing_keys={'password'},
            assert_sslcert=None,
            assert_sslkey=None,
            assert_preserved_params={},
        )),

        # 7. Regression: normal mode passes sslcert/sslkey from
        #    connection_params through unchanged.
        ('normal_mode_passes_cert_from_params', dict(
            connection_params={
                'sslcert': '/home/user/client.crt',
                'sslkey': '/home/user/client.key',
            },
            strip_keys=None,
            inject_params=None,
            call_user='postgres',
            call_password=None,
            assert_user='postgres',
            assert_not_user=None,
            assert_has_keys={'sslcert', 'sslkey'},
            assert_missing_keys={'password'},
            # get_complete_file_path is mocked to identity; absolute paths
            # pass through unchanged.
            assert_sslcert='/home/user/client.crt',
            assert_sslkey='/home/user/client.key',
            assert_preserved_params={},
        )),
    ]

    def _make_mock_manager(self):
        """Return a minimal ServerManager-like mock."""
        m = MagicMock()
        m.host = 'localhost'
        m.port = 5432
        m.use_ssh_tunnel = False
        m.local_bind_port = 5432
        m.local_bind_host = '127.0.0.1'
        m.service = None
        m.connection_params = self.connection_params
        return m

    def runTest(self):
        from psycopg.conninfo import conninfo_to_dict
        from pgadmin.utils.driver.psycopg3.server_manager import \
            ServerManager

        mock_manager = self._make_mock_manager()

        # get_complete_file_path: return the value unchanged for absolute paths
        # (mirrors real behaviour for already-absolute paths).
        with patch(
            'pgadmin.utils.driver.psycopg3.server_manager.get_complete_file_path',
            side_effect=lambda p: p
        ):
            result = ServerManager.create_connection_string(
                mock_manager,
                'testdb',
                self.call_user,
                password=self.call_password,
                strip_keys=self.strip_keys,
                inject_params=self.inject_params,
            )

        parsed = conninfo_to_dict(result)

        # User assertion
        self.assertEqual(
            parsed.get('user'), self.assert_user,
            msg=f"Expected user='{self.assert_user}', got '{parsed.get('user')}'"
        )
        if self.assert_not_user:
            self.assertNotEqual(
                parsed.get('user'), self.assert_not_user,
                msg=f"user must not be '{self.assert_not_user}' (stored server username)"
            )

        # Keys that must be present
        for key in self.assert_has_keys:
            self.assertIn(
                key, parsed,
                msg=f"Expected '{key}' to be present in DSN"
            )

        # Keys that must be absent
        for key in self.assert_missing_keys:
            self.assertNotIn(
                key, parsed,
                msg=f"'{key}' must not appear in DSN for passthrough mode"
            )

        # Cert values
        if self.assert_sslcert is not None:
            self.assertEqual(
                parsed.get('sslcert'), self.assert_sslcert,
                msg=f"sslcert should be the system config path, got '{parsed.get('sslcert')}'"
            )
        if self.assert_sslkey is not None:
            self.assertEqual(
                parsed.get('sslkey'), self.assert_sslkey,
                msg=f"sslkey should be the system config path, got '{parsed.get('sslkey')}'"
            )

        # Other params preserved
        for k, v in self.assert_preserved_params.items():
            self.assertEqual(
                parsed.get(k), v,
                msg=f"connection_param '{k}' should be preserved as '{v}', "
                    f"got '{parsed.get(k)}'"
            )
