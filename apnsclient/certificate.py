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

import logging
import OpenSSL

# python 3 support
import six

__all__ = ('Certificate', )

# module level logger, defaults to apnsclient.certificate
LOG = logging.getLogger(__name__)


class Certificate(object):
    """ Default certificate loader. """
    # The way how to compare certificates. If None, then certificate body will be
    # dumped as bytestring and compared. Other option is to provide digest method
    # supported by pyOpenSSL. Certificates are considered equal if their digests
    # are equal.
    equality_check = 'sha1'

    def __init__(self, cert_string=None, cert_file=None, key_string=None, key_file=None, passphrase=None):
        """ Provider's certificate and private key.
        
            Your certificate will probably contain the private key. Open it
            with any text editor, it should be a plain text (PEM format). The
            certificate is enclosed in ``BEGIN/END CERTIFICATE`` strings and
            private key is in ``BEGIN/END RSA PRIVATE KEY`` section. If you can
            not find the private key in your .pem file, then you should
            provide it with `key_string` or `key_file` argument.

            .. note::
                If your private key is secured by a passphrase, then
                `pyOpenSSL` will query it from `stdin`. If your application is
                not running in the interactive mode, then don't protect your
                private key with a passphrase or use `passphrase` argument. The
                latter option is probably a big mistake since you are exposing
                the passphrase in your source code.

            :Arguments:
                - cert_string (bytes): certificate in PEM format from string.
                - cert_file (str): certificate in PEM format from file.
                - key_string (bytes): private key in PEM format from string.
                - key_file (str): private key in PEM format from file.
                - passphrase (bytes): passphrase for your private key.
        """
        self._context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv3_METHOD)
        if not isinstance(passphrase, six.binary_type):
            passphrase = six.b(passphrase)
        
        if cert_file:
            # we have to load certificate for equality check. there is no
            # other way to obtain certificate from context.
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Certificate provided as file: %s", cert_file)

            with open(cert_file, 'rb') as fp:
                cert_string = fp.read()
        else:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Certificate provided as string")

        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_string)
        self._context.use_certificate(cert)

        if not key_string and not key_file:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Private key provided with certificate %s %s passphrase",
                            'file' if cert_file else 'string',
                            'with' if passphrase is not None else 'without')

            # OpenSSL is smart enought to locate private key in the certificate
            args = [OpenSSL.crypto.FILETYPE_PEM, cert_string]
            if passphrase is not None:
                args.append(passphrase)

            pk = OpenSSL.crypto.load_privatekey(*args)
            self._context.use_privatekey(pk)
        elif key_file and passphrase is None:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Private key provided as file without passphrase: %s", key_file)

            self._context.use_privatekey_file(key_file, OpenSSL.crypto.FILETYPE_PEM)
        else:
            if key_file:
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("Private key provided as file withpassphrase: %s", key_file)

                # key file is provided with passphrase. context.use_privatekey_file
                # does not use passphrase, so we have to load the key file manually.
                with open(key_file, 'rb') as fp:
                    key_string = fp.read()
            else:
                if LOG.isEnabledFor(logging.DEBUG):
                    LOG.debug("Private key provided as string % passphrase",
                                'with' if passphrase is not None else 'without')

            args = [OpenSSL.crypto.FILETYPE_PEM, key_string]
            if passphrase is not None:
                args.append(passphrase)

            pk = OpenSSL.crypto.load_privatekey(*args)
            self._context.use_privatekey(pk)

        # check if we are not passed some garbage
        self._context.check_privatekey()

        # we use certificates as keys in connection pool, so we need equality check.
        # the method may differ depending on your preference.
        self._init_equality_check(cert)

    def _init_equality_check(self, cert):
        """ Initialize equality check used to compare certificates. """
        if self.equality_check is None:
            self._equality = cert.OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        else:
            self._equality = cert.digest(self.equality_check)

    def get_context(self):
        """ Returns SSL context instance.

            You may use that context to specify required verification level,
            trusted CA's etc.
        """
        return self._context

    def __hash__(self):
        """ Content based hash. """
        return hash(self._equality)

    def __eq__(self, other):
        """ True if other object is Certificate instance and it passes the equality check. """
        if isinstance(other, Certificate):
            return self._equality == other._equality

        return False
