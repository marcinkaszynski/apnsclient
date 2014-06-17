import os.path

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='apns-client',
    version='0.2.1',
    author='Sardar Yumatov',
    author_email='ja.doma@gmail.com',
    url='https://bitbucket.org/sardarnl/apns-client',
    description='Python client for Apple Push Notification service (APNs)',
    long_description=read('README.rst'),
    packages=['apnsclient', 'apnsclient.backends'],
    license="Apache 2.0",
    keywords='apns push notification apple messaging iOS',
    install_requires=['pyOpenSSL', 'six'],
    classifiers = [ 'Development Status :: 4 - Beta',
                    'Intended Audience :: Developers',
                    'License :: OSI Approved :: Apache Software License',
                    'Programming Language :: Python',
                    'Topic :: Software Development :: Libraries :: Python Modules']
)
