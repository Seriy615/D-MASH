"""Offline regression: canonical endpoint migration preserves unrelated authority."""
import unittest
from migrate_ems_domain import hostname, replace_settings, nginx_site, PATHS
from provision_ems_proxy_tls import http_server, tls_server


class DomainMigrationTests(unittest.TestCase):
    def test_host_rejects_configuration_injection_and_urls(self):
        self.assertEqual(hostname('proxy.d-mash.ru'), 'proxy.d-mash.ru')
        for value in ['https://proxy.d-mash.ru', 'proxy.d-mash.ru/x', 'proxy.d-mash.ru:443', 'proxy.d-mash.ru;\nx', 'Proxy.d-mash.ru', '-proxy.d-mash.ru', '127.0.0.1']:
            with self.assertRaises(ValueError):
                hostname(value)

    def test_env_preserves_flags_and_credentials_exactly(self):
        original='# retained\nDMASH_CAN_S_TURN=0\nDMASH_TURN_SHARED_SECRET_B64=opaque-fixture\nDMASH_OTHER_POLICY=1\nDMASH_SIGNALING_WSS=wss://obsolete.invalid/signal/v1\n'
        settings={'DMASH_SIGNALING_WSS':'wss://proxy.d-mash.ru/signal/v1','DMASH_TURN_URLS':'turn:proxy.d-mash.ru:3479?transport=udp'}
        result=replace_settings(original, settings)
        self.assertTrue(result.startswith(original.split('DMASH_SIGNALING_WSS=')[0]))
        self.assertEqual(replace_settings(result,settings),result)
        with self.assertRaises(ValueError):
            replace_settings('DMASH_SIGNALING_WSS=a\nDMASH_SIGNALING_WSS=b\n',settings)

    def test_turn_preserves_realm_secret_and_resource_flags(self):
        original='realm=previous.realm\nstatic-auth-secret=opaque-fixture\nlistening-port=3479\nuser-quota=8\nserver-name=obsolete.invalid\n'
        result=replace_settings(original,{'server-name':'proxy.d-mash.ru'})
        self.assertEqual(result,original.replace('obsolete.invalid','proxy.d-mash.ru'))

    def test_exact_proxy_paths_default_deny_and_other_servers_preserved(self):
        unrelated='server { listen 443 ssl; server_name messenger.d-mash.ru; location / { root /srv/pwa; } }\n'
        site=http_server('proxy.d-mash.ru','/var/lib/letsencrypt')+tls_server('proxy.d-mash.ru')
        migrated=nginx_site(unrelated+site,'proxy.d-mash.ru')
        self.assertTrue(migrated.startswith(unrelated))
        self.assertEqual(nginx_site(migrated,'proxy.d-mash.ru'),migrated)
        for route in PATHS:
            self.assertEqual(migrated.count('location = '+route+' {'),1)
        self.assertIn('location = /dmash-client/v3 {\n        proxy_pass http://127.0.0.1:18080/dmp-c/v3;', migrated)
        self.assertIn('location / { return 404; }',migrated)
        self.assertNotIn('stage-api-ems',migrated)
        self.assertNotIn('proxy_pass http://127.0.0.1:18080/dmash-client/v1;',migrated)
        self.assertEqual(migrated.count('proxy_pass http://127.0.0.1:18080/dmp-c/v3;'),3)

    def test_refuses_wrong_vhost_or_conflicting_unmanaged_locations(self):
        site=tls_server('proxy.d-mash.ru')
        for invalid in [site.replace('proxy.d-mash.ru','wrong.invalid'),site+site,site.replace('# BEGIN D-MASH canonical exact endpoints','# unmanaged').replace('# END D-MASH canonical exact endpoints','# unmanaged'),site.replace('listen 443 ssl','listen 80')]:
            with self.assertRaises(ValueError):
                nginx_site(invalid,'proxy.d-mash.ru')


if __name__=='__main__':
    unittest.main()
