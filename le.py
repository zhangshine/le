#!/usr/bin/env python
import argparse
import base64
import copy
import hashlib
import json
import os
import subprocess

import binascii
import textwrap
import requests
import time
import sys

CA = 'https://acme-v01.api.letsencrypt.org'

# https://tools.ietf.org/html/rfc7519
# https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-6.3


def b64(b):
    # https://github.com/letsencrypt/letsencrypt/blob/74b2e3bc515b5f7e805883a26f1b0e47ed686098/acme/acme/jose/b64.py#L21
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).decode().rstrip('=')  # replace '=' with space ?


def get_replay_nonce():
    # Get replay-nonce https://acme-v01.api.letsencrypt.org/directory
    r = requests.head('{0}/directory'.format(CA))
    reg_nonce = r.headers['Replay-Nonce']
    return reg_nonce


def get_key_modulus(key_file_path):
    """
    https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-6.3.1.2

    openssl rsa -pubin -in user.pub -modulus -noout

    :param key_file_path:
    :return:
    """
    p = subprocess.Popen(['openssl', 'rsa', '-in', key_file_path, '-modulus', '-noout'],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()

    if p.returncode != 0:
        raise ValueError('Get key modulus failed:\n{err}'.format(err=err.decode()))

    out = out.strip()
    prefix = b'Modulus='
    if not out.startswith(prefix):
        raise ValueError('Bad modules: {m}'.format(m=out))

    modulus = out[len(prefix):]
    return modulus


def get_key_modulus_base64(key_path):
    return b64(binascii.unhexlify(get_key_modulus(key_path)))


def get_key_exponent_base64(exp=65537):
    return b64(binascii.unhexlify('0{0:x}'.format(exp)))


class LetsEncryptRateLimitException(Exception):
    pass


class LetsEncrypt(object):
    def __init__(self, user_key_path, domain, domain_csr_path, acme_dir):
        self.user_key_path = user_key_path
        self.header = self.get_header()
        self.domain = domain
        self.domain_csr_path = domain_csr_path
        self.acme_dir = acme_dir

    def get_header(self):
        return {
            'alg': 'RS256',
            'jwk': {
                'e': get_key_exponent_base64(),
                'kty': 'RSA',
                'n': get_key_modulus_base64(self.user_key_path)
            }
        }

    def _send_signed_request(self, url, payload):
        nonce = get_replay_nonce()
        payload64 = b64(json.dumps(payload, sort_keys=True, separators=(',', ':')))

        protected = copy.deepcopy(self.header)
        protected.update({'nonce': nonce})
        protected64 = b64(json.dumps(protected))

        p = subprocess.Popen(['openssl', 'dgst', '-sha256', '-sign', self.user_key_path], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(input='{0}.{1}'.format(protected64, payload64).encode())
        data = json.dumps({
            'header': self.header,
            'protected': protected64,
            'payload': payload64,
            'signature': b64(out)
        })

        r = requests.post(url, data)
        return r

    def user_register(self):
        r = self._send_signed_request(CA + '/acme/new-reg', {
            'resource': 'new-reg',
            'agreement': 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf'
        })

        if r.status_code in [201, 409]:
            return True
        else:
            raise ValueError('Register user failed: {code} {err}'.format(r.status_code, r.content))

    def write_challenge_file(self, token):
        user_key_json = json.dumps(self.header['jwk'], sort_keys=True, separators=(',', ':'))  # eliminate space
        thumb_print = b64(hashlib.sha256(user_key_json.encode()).digest())

        key_authorization = '{0}.{1}'.format(token, thumb_print)

        # write challenge to file
        key_authorization_path = os.path.join(self.acme_dir, token)
        with open(key_authorization_path, 'w') as f:
            f.write(key_authorization)

        return key_authorization_path, key_authorization

    def notify_acme_we_are_ready(self, challenge_url, key_authorization):
        r = self._send_signed_request(challenge_url, {
            'resource': 'challenge',
            'keyAuthorization': key_authorization
        })

        if r.status_code != 202:
            raise ValueError('Notify Acme server failed: {code} {err}'.format(code=r.status_code, err=r.content))

    def waiting_domain_verification(self, challenge_url, key_authorization_path):
        while True:
            r = requests.get(challenge_url)

            status = r.json()['status']
            if status == 'pending':
                pass
            elif status == 'valid':
                os.remove(key_authorization_path)
                break
            else:
                raise ValueError('Bad status: {code} {err}'.format(code=r.status_code, err=r.content))

            time.sleep(2)

    def get_signed_certificate(self):
        p = subprocess.Popen(['openssl', 'req', '-in', self.domain_csr_path, '-outform', 'DER'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        domain_csr_der, err = p.communicate()
        r = self._send_signed_request(CA + '/acme/new-cert', {
            'resource': 'new-cert',
            'csr': b64(domain_csr_der)
        })

        if r.status_code == 429:
            raise LetsEncryptRateLimitException(r.content.decode())
        elif r.status_code != 201:
            raise ValueError('Error signing certificate: {code} {err}'.format(
                code=r.status_code, err=r.content.decode()
            ))

        return """-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n""".format(
            "\n".join(textwrap.wrap(base64.b64encode(r.content).decode(), 64))
        )

    def get_challenge_info(self):
        r = self._send_signed_request(CA + '/acme/new-authz', {
            'resource': 'new-authz',
            'identifier': {
                'type': 'dns',
                'value': self.domain
            }
        })

        if r.status_code != 201:
            raise ValueError('Start new authentication failed: {code} {err}'.format(code=r.status_code, err=r.content))

        # challenge info
        return [c for c in r.json()['challenges'] if c['type'] == 'http-01'][0]

    def check_if_challenge_available(self, token):
        url = 'http://{domain}/.well-known/acme-challenge/{token}'.format(domain=self.domain, token=token)
        r = requests.get(url)
        if r.status_code != 200:
            raise ValueError('Challenge file server configuration is wrong: {code} {err}'.format(
                code=r.status_code, err=r.content
            ))

    def sign_domain(self):
        challenge = self.get_challenge_info()

        token = challenge['token']
        key_authorization_path, key_authorization = self.write_challenge_file(token)

        # check that the file is in place
        self.check_if_challenge_available(token)

        # notify acme we are ready
        challenge_url = challenge['uri']
        self.notify_acme_we_are_ready(challenge_url, key_authorization)

        # waiting domain verified
        self.waiting_domain_verification(challenge_url, key_authorization_path)

        # send domain cert
        return self.get_signed_certificate()

    def __call__(self):
        self.user_register()
        return self.sign_domain()


def generate_key(key_path):
    p = subprocess.Popen(['openssl', 'genrsa', '4096'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        raise ValueError('Generate key failed: {0} {1}'.format(key_path, err))

    with open(key_path, 'wb') as f:
        f.write(out)


def generate_domain_csr(domain, domain_key_path, domain_csr_path):
    p = subprocess.Popen(
        ['openssl', 'req', '-new', '-sha256', '-key', domain_key_path, '-subj', '/CN={0}'.format(domain)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = p.communicate()
    if p.returncode != 0:
        raise ValueError('Generate domain csr file failed: {domain} {domain_key_path} {domain_csr_path}\n{err}'.format(
            domain=domain, domain_key_path=domain_key_path, domain_csr_path=domain_csr_path, err=err.decode()
        ))

    with open(domain_csr_path, 'w') as f:
        f.write(out.decode())


def append_lets_encrypt_intermediate_cert(cert):
    """
    append the Let's Encrypt intermediate cert
    :return:
    """
    r = requests.get('https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem')
    if r.status_code != 200:
        raise ValueError('Got Let\'s Encrypt intermediate cert failed.')

    return "{0}\n{1}".format(cert, r.content.decode())


def main():
    parser = argparse.ArgumentParser(description='Sign domain')
    parser.add_argument('domain', metavar='Domain', type=str, help='domain to be signed')
    parser.add_argument('acme_dir', metavar='DcmeDir', type=str, help='Wellknown change file destination')
    parser.add_argument('--user-key-path', dest='user_key_path', help='User key file path')
    parser.add_argument('--domain-csr-path', dest='domain_csr_path', help='Domain csr file path')
    parser.add_argument('--output', dest='output', help='Write signed cert to an output file')

    args = parser.parse_args()
    domain = args.domain
    acme_dir = args.acme_dir
    base_dir = os.path.dirname(__file__)

    user_key_path = args.user_key_path
    if not user_key_path:
        user_key_path = os.path.join(base_dir, 'certs', 'user.key')
        if not os.path.exists(user_key_path):
            generate_key(user_key_path)

    domain_csr_path = args.domain_csr_path
    if not domain_csr_path:
        domain_csr_path = os.path.join(base_dir, 'certs', '{0}.csr'.format(domain))
        if not os.path.exists(domain_csr_path):
            domain_key_path = os.path.join(base_dir, 'certs', '{0}.key'.format(domain))
            generate_key(domain_key_path)
            generate_domain_csr(domain, domain_key_path, domain_csr_path)

    cert = LetsEncrypt(user_key_path, domain, domain_csr_path, acme_dir)()
    # cert = append_lets_encrypt_intermediate_cert(cert)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(cert)
    else:
        sys.stdout.write(cert)

if __name__ == '__main__':
    main()
