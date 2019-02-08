import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APICException(Exception):
    pass

class APICTimeout(APICException):
    pass

class APICError(APICException):
    pass

class APIC():
    apic_cookie = None

    def __init__(self,apic_ip,apic_user,apic_password,auth_retries=3,verify_ssl=False,timeout=5):
        self.apic_ip = apic_ip
        self.apic_user = apic_user
        self.apic_password = apic_password
        self.auth_retries = auth_retries
        self.verify_ssl = False
        self.timeout = timeout
    
    def connect(self):
        '''
        Initiate a new connection to an APIC. This will authenticate and store the session cookie which is used later on.
        If this function is not called manually it will be automatically when request_wrap is initiated as a 403 will be returned from the APIC.
        '''
        try:
            auth_url = f'https://{self.apic_ip}/api/mo/aaaLogin.xml'
            auth_xml = f'<aaaUser name="{self.apic_user}" pwd ="{self.apic_password}"/>'
            session = requests.post(auth_url, data=auth_xml, verify=self.verify_ssl, timeout=self.timeout)
            if session.status_code != 200:
                raise APICError(f'Unable to connect to {self.apic_ip} HTTP code: {session.status_code}')
            self.apic_cookie = session.cookies
        except requests.exceptions.Timeout:
            raise APICTimeout(f'APIC {self.apic_ip} timed out.')
        finally:
            return session.status_code
        
    def request_wrap(self,method,url,data=None,**kwargs):
        '''
        Wraps a raw request to the APIC with retries, POST & GET.
        Returns a requests response object. If the call fails an empty object will be returned and an exception raised.
        '''
        for attempt in range(self.auth_retries):
            status = None
            try:
                if method == 'POST':
                    status = requests.post(f'https://{self.apic_ip}/{url}', data=data, cookies=self.apic_cookie, verify=False, **kwargs)
                elif method == 'GET':
                    status = requests.get(f'https://{self.apic_ip}/{url}', cookies=self.apic_cookie, verify=False, **kwargs)
                else:
                    raise APICError(f'Unknown method {method}')
            except TimeoutError:
                self.connect()
                continue
            if status.status_code == 403:
                self.connect()
                continue
            else: return status
        raise APICError(f'Unable to {method} to {self.apic_ip} tried to re-auth {self.auth_retries} times. Check username & password. Response: {status.text}')

    def post_raw(self,url,data):
        return self.request_wrap('POST',url,data)

    def get(self,url):
        return self.request_wrap('GET',url)

    def post_policy(self,method,data):
        method = method.lower()
        assert method in ('xml','json'), 'Method should be XML or JSON'
        url = f'api/policymgr/mo/.{method}'
        return self.post_raw(url,data)

    def post_xml(self, xmldata):
        return self.post_policy('xml',xmldata)

    def post_json(self, xmldata):
        return self.post_policy('json',xmldata)
