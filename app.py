#########################################################################
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
import sys
import urllib
from flask import redirect, request, render_template, session, Flask
from flask_oidc_ext import OpenIDConnect
from oauth2client.client import OAuth2Credentials
import requests
_app = Flask(__name__)

_app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'settings.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'flask-demo',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'API_URL' : 'http://api.example.com/api/pet/findByStatus?status=available' 
})
oidc = OpenIDConnect(_app)



@_app.route('/')
def index():
    """
    :return: the index page with the tokens, if set.
    """
    if "api_url" not in session :
        session["api_url"] = _app.config.get("API_URL")
    if session["api_url"] is None or  session["api_url"]== '' :    
        session["api_url"] = _app.config.get("API_URL")
    _app.logger.debug("default route /")
    if oidc.user_loggedin:
        _app.logger.debug("logged")
        return render_template('index.html')
        
    else:
        _app.logger.debug("not logged")
        return render_template('welcome.html')
    

@_app.route('/start-login')
@oidc.require_login
def start_code_flow():
    """
    :return: redirects to the authorization server with the appropriate parameters set.
    """
    _app.logger.debug("start_code_flow")
    return render_template('index.html')


@_app.route('/logout')
def logout():
    """
    Logout clears the session, along with the tokens
    :return: redirects to /
    """
    return render_template('welcome.html')
        
   


@_app.route('/call-api')
@oidc.require_login
def call_api():
    """
    Call an api using the Access Token
    :return: the index template with the data from the api in the parameter 'data'
    """
    url = request.args.get('url')
    if url is None:
        return render_template('index.html', e = "Pas d'url valide")
    
    api_url = url
    
    session["api_url"] = api_url
    info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])
    
    username = info.get('preferred_username')
    email = info.get('email')
    user_id = info.get('sub')
    _app.logger.info("username %s" % username)
    _app.logger.info("email %s" % email)
    _app.logger.info("user_id %s" % user_id)

    
    if not user_id in oidc.credentials_store:
        _app.logger.debug("no user_id is store")
        return redirect('/start-login')

    else:
        access_token = OAuth2Credentials.from_json(oidc.credentials_store[user_id]).access_token
        session["access_token"] = access_token
    try:
        
        _app.logger.debug("call api")
        
        
        session["id_token_json"] = OAuth2Credentials.from_json(oidc.credentials_store[user_id]).id_token_jwt
        print('access_token=<%s>' % access_token)
        headers = {'Authorization': 'Bearer %s' % (access_token)}
        # YOLO
        _app.logger.debug("call %s with header %s" % (api_url, str(headers) ))
        api_response = requests.get(api_url, headers=headers)
        if "api_response" not in session:
            session["api_response"] = {}
        session["api_response"]["data"] = api_response.text
        session["api_response"]["code"] = api_response.status_code
    except Exception as e:
        print("Could not access greeting-service")
        print(e)
    
    return render_template('index.html')

if __name__ == '__main__':
    # some default values
    

    _port = 5443
    
    _app.run('0.0.0.0', debug=True, port=_port, ssl_context=('keys/localhost.pem', 'keys/localhost.pem'))
