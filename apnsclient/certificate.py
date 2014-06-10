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

__all__ = ('BaseCertificate', )


class BaseCertificate(object):
    """ Default certificate loader. """
    # The way how to compare certificates. If None, then certificate body will
    # be dumped as bytestring and compared. Other option is to provide digest
    # method supported by your SSL implementation. Certificates are considered
    # equal if their digests are equal.
    equality_check = 'sha1'

    def __init__(self, cert_string=None, cert_file=None, key_string=None, key_file=None, passphrase=None):
        """ Provider's certificate and private key.
        
            Your certificate will probably contain the private key. Open it
            with any text editor, it should be a plain text (PEM format). The
            certificate is enclosed in ``BEGIN/END CERTIFICATE`` strings and
            private key is in ``BEGIN/END RSA PRIVATE KEY`` section. If you can
            not find the private key in your .pem file, then you should
            provide it with `key_string` or `key_file` argument.

            :Arguments:
                - cert_string (bytes): certificate in PEM format from string.
                - cert_file (str): certificate in PEM format from file.
                - key_string (bytes): private key in PEM format from string.
                - key_file (str): private key in PEM format from file.
                - passphrase (bytes): passphrase for your private key.
        """
        self.context, cert = self.load_context(
            cert_string=cert_string,
            cert_file=cert_file,
            key_string=key_string,
            passphrase=passphrase
        )
        if self.equality_check is None:
            self._equality = self.dump_certificate(cert)
        else:
            self._equality = self.dump_digest(cert, self.equality_check)

    def load_context(self, cert_string=None, cert_file=None, key_string=None, key_file=None, passphrase=None):
        """ Initialize and load certificate context.
            
            :Returns:
                (context, raw_certificate) the SSL context and raw certificate instance.
        """
        raise NotImplementedError

    def dump_certificate(self, raw_certificate):
        """ Dump certificate as PEM string.
        
            :Arguments:
                - raw_certificate (object): raw certificate as returned by :func:`load_context`

            :Returns:
                Certificate string as sequence of bytes.
        """
        raise NotImplementedError

    def dump_digest(self, raw_certificate, digest):
        """ Dump certificate digest.

            :Arguments:
                - raw_certificate (object): raw certificate as returned by :func:`load_context`
                - digest (str): digest name, such as "sha1"

            :Returns:
                Digest as sequence of bytes.
        """
        raise NotImplementedError

    def get_context(self):
        """ Returns SSL context instance. You may use that context to specify
            required verification level, trusted CA's etc.
        """
        return self.context

    def __hash__(self):
        """ Content based hash. """
        return hash(self._equality)

    def __eq__(self, other):
        """ True if other object is Certificate instance and it passes the equality check. """
        if hasattr(other, "_equality") and hasattr(other, "equality_check"):
            return self.equality_check == other.equality_check and self._equality == other._equality

        return False
