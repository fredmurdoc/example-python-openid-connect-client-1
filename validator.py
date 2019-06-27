##########################################################################
# Copyright 2016 Curity AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

import json
import urllib2
from jwkest import BadSignature
from jwkest.jwk import SYMKey, KEYS
from jwkest.jws import JWS
from tools import base64_urldecode
from tools import get_ssl_context
import logging
import sys

class JwtValidatorException(Exception):
    pass


class JwtValidator:
    def __init__(self, config):
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
        print 'Getting ssl context for jwks_uri'
        logging.info('Getting ssl context for jwks_uri')
        self.ctx = get_ssl_context(config)

        self.jwks_uri = config['jwks_uri']
        self.client_secret = config['client_secret'] 
        self.jwks = self.load_keys()

    def validate(self, jwt, iss, aud):
        parts = jwt.split('.')
        if len(parts) != 3:
            raise BadSignature('Invalid JWT. Only JWS supported.')
        header = json.loads(base64_urldecode(parts[0]))
        payload = json.loads(base64_urldecode(parts[1]))

        if iss != payload['iss']:
            raise JwtValidatorException("Invalid issuer %s, expected %s" % (payload['iss'], iss))

        if payload["aud"]:
            if (isinstance(payload["aud"], str) and payload["aud"] != aud) or aud not in payload['aud']:
                raise JwtValidatorException("Invalid audience %s, expected %s" % (payload['aud'], aud))

        jws = JWS(alg=header['alg'])
        # Raises exception when signature is invalid
        try:
            logging.debug('jws.verify_compact, length keys : %d' % (len(self.jwks)))
            jws.verify_compact(jwt, self.jwks)
            logging.debug('jws.verify_compact OK')
        except Exception as e:
            print "Exception validating signature"
            raise JwtValidatorException(e)
        print "Successfully validated signature."
        logging.info("Successfully validated signature.")

    def get_jwks_data(self):
        request = urllib2.Request(self.jwks_uri)        
        request.add_header('Accept', 'application/json')
        request.add_header('User-Agent', 'CurityExample/1.0')

        try:
            logging.debug("get_jwks_data to %s " % (self.jwks_uri))
            jwks_response = urllib2.urlopen(request, context=self.ctx)
            logging.debug("get_jwks_data loaded ")
        except Exception as e:
            print "Error fetching JWKS", e
            raise e
        return jwks_response.read()

    def load_keys(self):
        # load the jwk set.
        jwks = KEYS()
        try:
            logging.debug("load_keys")
            jwks.load_jwks(self.get_jwks_data())
            logging.debug("keys loaded")
        except Exception as e:
            print "Error in loading keys from endpoint, continue..."
        logging.debug("keys loaded %s " % (str(jwks)))
        logging.debug("create sym key")    
        key = SYMKey(key=self.client_secret)
        logging.debug("append sym key")    
        jwks.append(key)
        return jwks
