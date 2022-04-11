import csv
import sys
import json
import xlsxwriter
import datetime
from datetime import date
from datetime import datetime
from requests import post
from requests import get
import datetime


NEW_TWISTLOCK_USERNAME="f34b997f-58ea-4e45-a01d-1fb1337cbae8"
NEW_TWISTLOCK_PASSWORD="BPwISvyTdpEcuqULg5AURPYErrU="
NEW_TWISTLOCK_BASE_URL = "https://us-west1.cloud.twistlock.com/us-3-159181302"


class PrismaCloud():
    def __init__(self):
        self.token = self.__get_token()
        print(self.token)

    def __get_token(self):
        usr = NEW_TWISTLOCK_USERNAME
        psw = NEW_TWISTLOCK_PASSWORD
        data = {'username': usr, 'password': psw}
        resp = self.__api_post_auth_request(data)
        try:
            return resp['token']
        except KeyError:
            raise Exception('KeyError. Auth Response does not have a token')
        except Exception as e:
            exception_type = type(e).__name__
            exception_args = e.args
            raise Exception(
                f'UNKOWN ERROR - __get_token - ExceptionType: {exception_type}. Exception Args: {exception_args}')

    def __api_post_auth_request(self, params: dict):
        endpoint = 'api/v1/authenticate'
        return self.__api_post_request({}, params, endpoint)

    def __api_post_request(self, headers: dict, params: dict, endpoint: str):
        url = NEW_TWISTLOCK_BASE_URL + "/" + endpoint
        base_headers = {'Content-Type': 'application/json'}
        cust_headers = {**base_headers, **headers}
        resp = post(
            url,
            headers=cust_headers,
            data=json.dumps(params),
            verify=False
        )
        print(resp, resp.text)
        if resp.status_code == 401:
            raise Exception('Invalid credentials')
        elif resp.status_code == 500:
            raise Exception('Internal Server Error')
        elif resp.status_code == 505:
            raise Exception('Server Error: Service Unavailable')
        try:
            return resp.json()
        except ValueError:
            raise Exception('Unable to JSON decode API POST response')
        except Exception as e:
            exception_type = type(e).__name__
            exception_args = e.args
            raise Exception(
                f'UNKOWN ERROR. __api_post_request - ExceptionType: {exception_type}. Exception Args: {exception_args}')

    def __api_get_request(self, headers: dict, endpoint: str):
        base_headers = {'Content-Type': 'application/json'}
        cust_headers = {**base_headers, **headers}
        url = NEW_TWISTLOCK_BASE_URL + "/" + endpoint
        # print(url)
        resp = get(
            url,
            headers=cust_headers,
            verify=False
        )
        print(resp, resp.text, type(resp.text))
        if resp.status_code == 401:
            raise Exception('Invalid credentials')
        elif resp.status_code == 500:
            raise Exception('Internal Server Error')
        elif resp.status_code == 505:
            raise Exception('Server Error: Service Unavailable')
        try:
            return resp.json()
        except ValueError:
            raise Exception('Unable to JSON decode API POST response')
        except Exception as e:
            exception_type = type(e).__name__
            exception_args = e.args
            raise Exception(
                f'UNKOWN ERROR. __api_post_request - ExceptionType: {exception_type}. Exception Args: {exception_args}')

    def __api_get_offset_request(self, headers: dict, endpoint: str):
        base_headers = {'Content-Type': 'application/json'}
        cust_headers = {**base_headers, **headers}
        url = NEW_TWISTLOCK_BASE_URL + "/" + endpoint
        print(url)
        resp_list = []
        resp_list.sort()

        offset = 0
        #while True:
        if offset == 50:
            #    break
            response = get(url + "?limit=50&offset={}".format(offset), headers=cust_headers, verify=False)
            offset += 50
            #print("TEST", response.json())
            if response.json() == None:
                print("Got null response existing the while loop")
                print(offset)
               # break
            else:
                print(offset)
                print("Still in while loop added response output to list")
                resp_list += response.json()
        return resp_list

    def get_defenders(self):
        endpoint=f'api/v1/defenders'
        #endpoint = f'api/v1/images'
        token = self.__get_token()
        headers = {'Authorization': f'Bearer {token}'}
        return self.__api_get_offset_request(headers, endpoint)


# ##Initialize
connected = list()
prisma = PrismaCloud()
vuln_data = prisma.get_defenders()
for index, vuln in enumerate(vuln_data):
    #print(index, vuln.get('hostname'), vuln.get('connected'))
    #if vuln.get('connected'):
        #print(vuln.get('hostname'))
    connected.append([vuln.get('hostname'),
    vuln.get('version'), 
    vuln.get('lastModified'), 
    vuln.get('type'),
    vuln.get('category'),
    vuln.get('fqdn'),
    vuln.get('compatibleVersion'),])

#print(connected)
with open('disconnected.csv', 'w', newline='') as f:
    csv_writer = csv.writer(f)
    csv_writer.writerow(['Hostname', 'Version', 'Last Modified', 'Type', 'Category', 'FQDN', 'Compatible Version'])
    csv_writer.writerows(connected)

#print(vuln_data)
# vul_report_registry = prisma.get_all_high_low_critical_findings_for_registries()
sys.exit()