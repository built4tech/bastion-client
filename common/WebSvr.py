import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#SITE = "http://127.0.0.1:8000"
SITE = "http://built4tech.herokuapp.com"
URL_BASE = "/api/v1"

class WebService():
    def __init__(self, token):
        self.url_account = SITE + URL_BASE + "/account/"
        self.url_devices = SITE + URL_BASE + "/devices/"
        self.url_tools   = SITE + URL_BASE + "/tools/"
        self.token       = token

    def check_token(self):
        header  = {'Content-Type' : 'application/json','Authorization':'Token ' + self.token}

        try:
            r = requests.get(self.url_account, headers=header)
        except Exception as e:
            return ({'action' : 'failed', 'message' : 'Error checking if token is valid: %s'%e, 'function': 'WEBService, check_token'})

        data = {}
        if  r.status_code != 200:
            data['action'] = 'failed'
            data['message'] = r.json()
            data['function'] = 'WEBService, check_token'
        else:
            data['action'] = 'successful'
            data['message'] = r.json()
            data['function'] = 'WEBService, check_token'

        return(data)


    def ping(self):
        try:
            r = requests.get(self.url_tools + 'ping')
        except Exception as e:
            return ({'action' : 'failed', 'message' : 'Error getting ping: %s'%e, 'function': 'WEBService, ping'})

        if r.status_code == 200:
            try:
                return r.json()
            except Exception as e:
                return ({'action' : 'failed', 'message' : 'Error getting ping: %s'%e, 'function': 'WEBService, ping'})
        else:
            return ({'action' : 'failed', 'message' : 'Error getting ping', 'function': 'WEBService, ping'})
        
    def upload(self, payload):
        header  = {'Content-Type' : 'application/json','Authorization':'Token ' + self.token}
        
        try:
            r = requests.post(self.url_devices + 'create', json=payload, headers=header)
        except Exception as e:
            return({'action' : 'failed', 'message' : 'Error uploading host information: %s'%e, 'function': 'WEBService, upload'})

        # 401 es un error de autenticación con el token
        if r.status_code == 401:
            data = {}
            data['action'] = 'failed'
            data['message'] = r.json()
            data['function'] = 'WEBService, upload'
            return(data)

        return r.json()

    def getHosts2Enrich(self):
        header  = {'Content-Type' : 'application/json','Authorization':'Token ' + self.token}
        
    
        try:
            r = requests.get(self.url_devices + 'enrich', headers=header)
        except Exception as e:
            return({'action' : 'failed', 'message' : 'Error getting list of hosts to enrich: %s'%e, 'function': 'WEBService, getHost2Enrich'})

        # 401 es un error de autenticación con el token
       
        data = {}
        if r.status_code == 401:    
            data['action'] = 'failed'
            data['message'] = r.json()
            data['function'] = 'WEBService, upload'
        elif r.status_code == 200:
            data['action'] = 'successful'
            data['message'] = 'Sucessfully obtained list of hosts to be enriched'
            data['function'] = 'WEBService, getHost2Enrich'
            data['value'] = r.json()
        else:
            data['action'] = 'failed'
            data['message'] = r.json()
            data['function'] = 'WEBService, upload'
           
        return(data)


    def enrich(self, mac, payload):
        header  = {'Content-Type' : 'application/json','Authorization':'Token ' + self.token}

       
        try:
            r = requests.post(self.url_devices + '{}/enrich'.format(mac), json=payload, headers=header) 
        except Exception as e:
            return({'action' : 'failed', 'message' : 'Error enriching host information: %s'%e, 'function': 'WEBService, enrich'})

        # 401 es un error de autenticación con el token
        if r.status_code == 401:
            data = {}
            data['action'] = 'failed'
            data['message'] = r.json
            data['function'] = 'WEBService, upload'
            return(data)

        return r.json()

    