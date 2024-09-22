from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from javax.swing import JMenuItem
from java.io import PrintWriter
from java.util import List, ArrayList
import threading
import itertools
import time
import json

userA = {

}
userB = {

}


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        global userA,userB
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Header Fusion")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stdout.println("Header Fusion v1.0\nExtension Loaded")

        try:
            # parse utf data to normal dict
            def unicode_to_str(data):
                if isinstance(data, dict):
                    return {unicode_to_str(key): unicode_to_str(value) for key, value in data.items()}
                elif isinstance(data, list):
                    return [unicode_to_str(item) for item in data]
                elif isinstance(data, unicode):
                    return data.encode('utf-8')
                else:
                    return data

            with open('config.json', 'r') as f:
                data = json.load(f)

            dataList = []
            dataList = unicode_to_str(data)

            userA = dataList[0]['userA']
            userB = dataList[1]['userB']
            self.stdout.println("Config file loaded")
        except Exception as e:
            self.stdout.println("Error while parsing config.json "+str(e))

        # Register the context menu
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        # Create the context menu option
        menu = ArrayList()
        menu_item = JMenuItem(
            "Fuzz", actionPerformed=lambda x: self.process_request(invocation))
        menu.add(menu_item)
        return menu

    def process_request(self, invocation):
        threading.Thread(target=self._handle_request,
                         args=(invocation,)).start()


# capture each request sending to the tool

    def _handle_request(self, invocation):

        # Get the selected request
        messages = invocation.getSelectedMessages()

        if messages:

            for message in messages:

                request_info = self._helpers.analyzeRequest(message)

                original_url = request_info.getUrl()
                headers = request_info.getHeaders()
                prefix_list = userA.keys()
                mod_headers = []
                remainingHeaders = []

                # reduce the dict similar to request headers , remove unwanted headers
                def dict_reduce(temp_dict, mod_headers_dict_loc):
                    try:
                        reduce_ref = {key: value for key, value in temp_dict.items(
                        ) if key in mod_headers_dict_loc}
                        return reduce_ref
                    except Exception as e:
                        self.stdout.println(e)

                # convert list to dict
                def list_to_dict(temp_headers):
                    temp_dict = {}
                    try:
                        for i in temp_headers:
                            key, value = i.split(":")
                            header_dict = {
                                str(key.strip()): str(value.strip())}
                            temp_dict.update(header_dict)
                        return temp_dict
                    except Exception as e:
                        self.stdout.println(
                            "Error printing headers: " + str(e))

                for header in headers:
                    if any(header.lower().startswith(prefix.lower()) for prefix in prefix_list):
                        mod_headers.append(header)
                    else:
                        remainingHeaders.append(header)

                length_of_mod_headers = len(mod_headers)
                if (length_of_mod_headers > 0):

                    mod_headers_dict = list_to_dict(mod_headers)

                    def combination(ref_dict, mod_headers_dict_loc):
                        keys = ref_dict.keys()
                        combinations = list(itertools.product(
                            *[(mod_headers_dict_loc[key], reduce_ref[key]) for key in keys]))

                        # Create a list of dictionaries from the combinations
                        combination_dicts = [dict(zip(keys, combination))
                                             for combination in combinations]
                        return combination_dicts

                    def combine_headers(c_loc):
                        all_combined_headers_lists = []
                        try:
                            for i in c_loc:
                                all_headers = []
                                t = []
                                td = {}
                                td = i
                                for key, value in td.items():
                                    s = str(key)+": "+str(value)
                                    u = unicode(s, 'utf-8')
                                    t.append(u)
                                all_headers = remainingHeaders+t

                                all_combined_headers_lists.append(all_headers)
                            return all_combined_headers_lists
                        except Exception as e:
                            self.stdout.println(
                                "Error while combining: " + str(e))

                    # find user a or b
                    c = {}
                    all = []
                    if any(value in userA.values() for value in mod_headers_dict.values()):
                        self.stdout.println(
                            "\nRequest from user A \nAttack started for : " + str(original_url))
                        reduce_ref = dict_reduce(userB, mod_headers_dict)
                        c = combination(reduce_ref, mod_headers_dict)
                        all = combine_headers(c)

                    elif any(value in userB.values() for value in mod_headers_dict.values()):
                        self.stdout.println(
                            "\nRequest from user B\nAttack started for : " + str(original_url))
                        reduce_ref = dict_reduce(userA, mod_headers_dict)
                        c = combination(reduce_ref, mod_headers_dict)

                        all = combine_headers(c)

                    request = message.getRequest()
                    request_body = request[request_info.getBodyOffset():]
                    self.stdout.println(
                    )
                    for i in all:
                        new_request = self._helpers.buildHttpMessage(
                            i, request_body)
                        try:
                            response = self._callbacks.makeHttpRequest(
                                message.getHttpService(), new_request)
                            response_info = self._helpers.analyzeResponse(
                                response.getResponse())
                            response_code = response_info.getStatusCode()
                            self.stdout.println(
                                "\tModified request sent. Response code: " + str(response_code))
                        except Exception as e:
                            self.stdout.println(
                                "Error sending modified request: " + str(e))
                        time.sleep(1)
                else:
                    self.stdout.println(
                        "No Headers to swap for "+str(original_url)+"\n")
                break
