import argparse
import json
import logging
import requests
import sys
import time
import threading
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Poe_switch():
    csrf_token = None
    username = None
    password = None
    controller = None
    
    
    def __init__(self, controller, username, password):
        self.username = username
        self.password = password
        self.base_url = 'https://%s' % controller
        self.s = requests.Session()
        
    def logout(self):
        """Logout - this requires the X-CSRF-Token"""
        logout_endpoint = self.base_url + '/api/auth/logout'
        logging.info("Logging out via %s.", logout_endpoint)
        # UniFi OS versions before 3.2.7
        logout = self.s.post(logout_endpoint, headers = {'x-csrf-token': self.csrf_token}, verify = False, timeout = 5)
        # Unifi OS versions from 3.2.7
        # logout = self.s.post(logout_endpoint, headers = {'x-csrf-token': login.headers['X-Csrf-Token']}, verify = False, timeout = 5)

        if (logout.status_code == 200):
            logging.debug("Success.")
            sys.exit()
        else:
            logging.debug("Failed with return code %s", logout)
            sys.exit()

    def login(self):
        """Login and get auth token from Cookies plus X-CSRF-Token from header
        
        working call with cURL:  Login:
        curl -X POST --data 'username=user&password=pass' -c cookie.txt https://udm/api/auth/login
        Get status:
        curl -X GET -b cookie.txt https://udm/proxy/network/api/s/default/stat/device/abcdef01
        """
        
        login_endpoint = self.base_url + '/api/auth/login'

        logging.info("Trying to login to %s with username %s", login_endpoint, str(self.username))

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8"
        }

        login_data = {
            'username': self.username,
            'password': self.password
        }

        login = self.s.post(login_endpoint, headers = headers,  json = login_data , verify = False, timeout = 5)

        if (login.status_code == 200):
            cookies = login.cookies
            logging.debug("Success. Cookies received:")
            for c in cookies:
                logging.debug("%s ==> %s", c.name, c.value)
            self.csrf_token = login.headers.get('X-CSRF-Token', '')  # Retrieve the CSRF token
        else:
            logging.debug("Login failed with return code %s", login.status_code)
            sys.exit()

    def set_port_state(self, mac, ports_array, desired_poe_state):
        """Get current port_overrides config for device"""
        
        get_device_settings_endpoint = self.base_url + '/proxy/network/api/s/default/stat/device/%s' % mac
        logging.info ("Read current settings from %s", get_device_settings_endpoint)

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
        }
        r = self.s.get(get_device_settings_endpoint, headers = headers, verify = False, timeout = 5)

        if (r.status_code == 200):
            logging.debug("Success.")
        else:
            logging.debug("Failed with return code %s", r)
            self.logout()

        device_json = r.json()
        port_overrides = device_json['data'][0]['port_overrides']
        device_id = device_json['data'][0]['device_id']

        set_device_settings_endpoint = self.base_url + '/proxy/network/api/s/default/rest/device/'
        set_device_settings_endpoint = set_device_settings_endpoint + device_id

        # Update the port_overrides config with new settings
        for x in ports_array:
            for value in port_overrides:
                if value['port_idx'] == int(x):
                    if 'poe_mode' in value:
                        if (value['poe_mode'] != desired_poe_state):
                            logging.info("Updating port_idx %s from %s to %s", value['port_idx'], value['poe_mode'], desired_poe_state)
                            value['poe_mode'] = desired_poe_state
                        else:
                            logging.info("port_idx %s already set to %s", value['port_idx'], desired_poe_state)


        # Set the updated port_overides config for device
        new_port_overrides = { 'port_overrides': port_overrides }

        logging.info("Trying to update port overrides on %s", set_device_settings_endpoint)

        logging.debug("%s", json.dumps(new_port_overrides))

        # UniFi OS versions before 3.2.7
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "x-csrf-token": self.csrf_token
        }

        # UniFi OS versions from 3.2.7
        #headers = {
        #    "Accept": "application/json",
        #    "Content-Type": "application/json; charset=utf-8",
        #    "x-csrf-token": login.headers['X-Csrf-Token']
        #}

        update = self.s.put(set_device_settings_endpoint, headers = headers, data = json.dumps(new_port_overrides), verify = False, timeout = 5)

        if (update.status_code == 200):
            logging.debug("Success.")
        else:
            logging.debug("Failed with return code %s", update.status_code)

    def monitor_url(self, mac, ports_array, desired_poe_state):
        """Monitor URL for success and perform actions when it fails"""
        while True:
            try:
                logging.info("Monitoring URL: %s", args.monitor_url)
                response = requests.get(args.monitor_url, verify=False, timeout=5)
                if response.status_code == 200:
                    logging.info("Monitoring URL successful.")
                else:
                    logging.warning("Monitoring URL failed with status code %s", response.status_code)
                    # Perform actions when the URL is not successful
                    self.login()
                    self.set_port_state(mac, ports_array, 'off')
                    time.sleep(5)
                    self.set_port_state(mac, ports_array, 'auto')
                    self.logout()
            except Exception as e:
                logging.warning("Error while monitoring URL: %s", str(e))
            time.sleep(args.monitor_interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Change the PoE Mode of UniFi switches controlled by a UDM (Pro).')
    parser.add_argument("controller", help="hostname or IP address of UniFi Controller")
    parser.add_argument("username", help="username with admin rights on UniFi Controller")
    parser.add_argument("password", help="corresponding password for admin user")
    parser.add_argument("mac", help="MAC address (with or without colons) of switch")
    parser.add_argument("ports", help="port numbers to acquire new state (list separated by comma, e.g., '5,6,7'")
    parser.add_argument("state", help="desired state of PoE ports, e.g., 'auto' or 'off'")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("--monitor_url", help="URL to monitor for success")
    parser.add_argument("--monitor_interval", type=int, default=60, help="Interval in seconds to monitor the URL (default: 60)")
    args=parser.parse_args()

    if (args.verbose):
        loglevel=logging.DEBUG
    else:
        loglevel=logging.INFO

    logging.basicConfig(level=loglevel, format='%(asctime)s - %(levelname)s - %(message)s')


    # Start monitoring if monitor_url is provided
    if args.monitor_url:
        monitor_thread = threading.Thread(target=monitor_url)
        monitor_thread.start()
    else:
        ports_array = args.ports.split(',')
        desired_poe_state = args.state
        
        poe_switch = Poe_switch(args.controller, args.username, args.password)
        poe_switch.login()
        poe_switch.set_port_state(args.mac, ports_array, desired_poe_state)
        poe_switch.logout()
