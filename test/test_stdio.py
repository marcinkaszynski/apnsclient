# Copyright 2014 Sardar Yumatov
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if __name__ == '__main__':
    import os.path, sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import unittest, datetime
from apnsclient import Session


CERTIFICATE = b"""-----BEGIN CERTIFICATE-----
MIIDPTCCAuegAwIBAgIJALpcHuGZGDLzMA0GCSqGSIb3DQEBBQUAMIGdMQswCQYD
VQQGEwJOTDESMBAGA1UECBMJR3JvbmluZ2VuMRIwEAYDVQQHEwlHcm9uaW5nZW4x
FDASBgNVBAoTC2FwbnMtY2xpZW50MRUwEwYDVQQLEwxjZXJ0aWZpY2F0ZXMxFzAV
BgNVBAMTDlNhcmRhciBZdW1hdG92MSAwHgYJKoZIhvcNAQkBFhFqYS5kb21hQGdt
YWlsLmNvbTAeFw0xNDA1MjUxMjEwMjNaFw0xNDA2MjQxMjEwMjNaMIGdMQswCQYD
VQQGEwJOTDESMBAGA1UECBMJR3JvbmluZ2VuMRIwEAYDVQQHEwlHcm9uaW5nZW4x
FDASBgNVBAoTC2FwbnMtY2xpZW50MRUwEwYDVQQLEwxjZXJ0aWZpY2F0ZXMxFzAV
BgNVBAMTDlNhcmRhciBZdW1hdG92MSAwHgYJKoZIhvcNAQkBFhFqYS5kb21hQGdt
YWlsLmNvbTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC8hz/oFmBrSXpVwipPxFxZ
qzSGgojSVxM/Mzaf24l/b9oeszfnrq0owk40PG7InSv6l5Z71SXKIOLKwJBgI8Od
AgMBAAGjggEGMIIBAjAdBgNVHQ4EFgQUW0eeuZwjTcf1irE+11/C8fF2tSowgdIG
A1UdIwSByjCBx4AUW0eeuZwjTcf1irE+11/C8fF2tSqhgaOkgaAwgZ0xCzAJBgNV
BAYTAk5MMRIwEAYDVQQIEwlHcm9uaW5nZW4xEjAQBgNVBAcTCUdyb25pbmdlbjEU
MBIGA1UEChMLYXBucy1jbGllbnQxFTATBgNVBAsTDGNlcnRpZmljYXRlczEXMBUG
A1UEAxMOU2FyZGFyIFl1bWF0b3YxIDAeBgkqhkiG9w0BCQEWEWphLmRvbWFAZ21h
aWwuY29tggkAulwe4ZkYMvMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAANB
AGwgOsUkTIo1y9v3Y77r02RjJLQRL1P68J8Exiunc53LR97Cg+o7LmaHonaLTUUH
jahmYuZGN/Mty0brOn9hTI0=
-----END CERTIFICATE-----"""

PRIVATE_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,3195B956C3AD71F6

g7mfzdit5/26briSho71co+eqHV4Xxw7Y/lJzjuN7SGFjUbh/mBNjOxNmXzVSBWo
50SH/NgyqW7wy4glVLIdZ7u7iR8JZjXeBmH1Aee7+4TLGT5fTDR5aYWW7EPIRJ+E
fAgEm1A0fsiHf7ki++UAFtZTPVcQg1NGeYjkJmpgn4CQwyztcfq1psIvNBBgAdrG
UkHeJvwMalS/cmnVVdH2jR2liCsJhfH4lqH8eUSfGwCBeEjAY0Lg6HPwZY+eiVay
/F5D8oL8GvqrM4hyzxU0KOZ8Pu0VUe1wDXDiNv3TUypZm5Y5sRi9DZ6jwZa7/hiE
h3nbwhSfx2WC3bN8Gs8G9pJV9LGiBY2y2zANYTrq7Mv3iVLkHY8BQIUYQuiUnT20
8jeLSXRfZauDrVW5a8wGSJJLAyHGbXMAMV81z129xf8=
-----END RSA PRIVATE KEY-----"""

PRIVATE_PASS= "test"


class Python26Mixin(object):
    """ Adds missing methods to test cases in Python 2.6 environment. """

    def assertIsNotNone(self, value, msg=None):
        """ Fail if value is None. """
        parent = super(Python26Mixin, self)
        if hasattr(parent, 'assertIsNotNone'):
            parent.assertIsNotNone(value, msg)
        else:
            if value is None:
                raise self.failureException(msg or '%r is None' % value)


class StdIOBackendTest(Python26Mixin, unittest.TestCase):
    """ Test stdio features. """

    def setUp(self):
        self.session = Session(pool="apnsclient.backends.stdio")

    def test_locking(self):
        """ Test thread locking mechanism """
        lock = self.session.pool.create_lock()
        self.assertIsNotNone(lock)
        self.assertTrue(hasattr(lock, "acquire"))
        self.assertTrue(hasattr(lock, "release"))
        lock.acquire()
        lock.release()

    def test_certificates(self):
        """ Test pyOpenSSL certificates. """
        cert = self.session.pool.get_certificate({
            "cert_string": CERTIFICATE,
            "key_string": PRIVATE_KEY,
            "passphrase": PRIVATE_PASS
        })

        cert2 = self.session.pool.get_certificate({
            "cert_string": (CERTIFICATE + b"\n" + PRIVATE_KEY),
            "passphrase": PRIVATE_PASS
        })

        self.assertIsNotNone(cert.get_context())
        self.assertEqual(cert, cert2)
        
    def test_outdate(self):
        # we are not allowed to do any IO in tests, so no real connections.
        # however, it is good idea to test utility functions even with empty pool.
        self.session.outdate(datetime.timedelta(seconds=60))
        self.session.shutdown()


if __name__ == '__main__':
    unittest.main()
