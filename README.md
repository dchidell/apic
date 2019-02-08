# apic
A very simple class for handling Cisco ACI APIC connections

Requires the following libraries:

requests
urllib3

# Example Usage:
```
>>> import APIC
>>> apic = APIC('10.0.0.1','admin','password')
>>> print(apic.get('api/policymgr/mo/.xml').text)
<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><topRoot childAction="" dn="" status=""/></imdata>
>>>
```
 
