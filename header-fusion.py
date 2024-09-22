from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import (
    JScrollPane, JPanel, JButton, JOptionPane,
    JTable, JFileChooser, BoxLayout, Box, JMenuItem
)
from javax.swing.table import AbstractTableModel
from java.util import ArrayList
from java.io import PrintWriter
import threading
import itertools
import time

userA = {

}
userB = {

}


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        global userA, userB
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Header Fusion")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stdout.println("Header Fusion v1.0\nExtension Loaded")

        # Create database
        self._dbA = MatrixDB(userA)
        self._dbB = MatrixDB(userB)

        # Create tables to display user headers
        self._userATable = UserTable(model=UserTableModel(self._dbA))
        self._userBTable = UserTable(model=UserTableModel(self._dbB))

        # Create panel for tables
        tablesPanel = JPanel()
        tablesPanel.setLayout(BoxLayout(tablesPanel, BoxLayout.X_AXIS))
        tablesPanel.add(JScrollPane(self._userATable))
        tablesPanel.add(JScrollPane(self._userBTable))

        # Create panel for buttons
        buttons = JPanel()
        buttons.setLayout(BoxLayout(buttons, BoxLayout.X_AXIS))

        # Create buttons for adding new headers, saving, loading, and clearing headers
        self._newUserAButton = JButton(
            "New User A", actionPerformed=self.getInputUserAClick)
        self._newUserBButton = JButton(
            "New User B", actionPerformed=self.getInputUserBClick)
        self._saveButton = JButton("Save", actionPerformed=self.saveClick)
        self._loadButton = JButton("Load", actionPerformed=self.loadClick)
        self._clearButton = JButton("Clear", actionPerformed=self.clearClick)

        buttons.add(self._newUserAButton)
        buttons.add(Box.createHorizontalStrut(5))
        buttons.add(self._newUserBButton)
        buttons.add(Box.createHorizontalStrut(5))
        buttons.add(self._saveButton)
        buttons.add(Box.createHorizontalStrut(5))
        buttons.add(self._loadButton)
        buttons.add(Box.createHorizontalStrut(5))
        buttons.add(self._clearButton)

        # Create main panel to hold the tables and buttons
        self.mainPanel = JPanel()
        self.mainPanel.setLayout(BoxLayout(self.mainPanel, BoxLayout.Y_AXIS))
        self.mainPanel.add(tablesPanel)
        self.mainPanel.add(buttons)

        # Register the UI components
        callbacks.customizeUiComponent(self.mainPanel)
        callbacks.addSuiteTab(self)

        # Register the context menu
        callbacks.registerContextMenuFactory(self)

    def getTabCaption(self):
        return "Header Fusion"

    def getUiComponent(self):
        return self.mainPanel

    def getInputUserAClick(self, event):
        self.getInputUserClick("A")

    def getInputUserBClick(self, event):
        self.getInputUserClick("B")

    def getInputUserClick(self, user):
        headerName = JOptionPane.showInputDialog(
            self.mainPanel, "Enter New Header Name for User {}:".format(user))
        if headerName and headerName.strip():
            headerValue = JOptionPane.showInputDialog(
                self.mainPanel, "Enter Header Value for User {}:".format(user))
            if headerValue is not None:
                # Store the new header in the appropriate dictionary
                if user == "A":
                    userA[headerName.strip()] = headerValue.strip()
                    self._dbA.updateData(userA)
                    self._userATable.redrawTable()
                else:
                    userB[headerName.strip()] = headerValue.strip()
                    self._dbB.updateData(userB)
                    self._userBTable.redrawTable()

    def saveClick(self, event):
        # Handle saving user data to a file
        options = ["User A", "User B"]
        choice = JOptionPane.showOptionDialog(
            self.mainPanel,
            "Select the user data to save:",
            "Save Data",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.INFORMATION_MESSAGE,
            None,
            options,
            options[0]
        )
        if choice == 0:  # User A selected
            self.saveHeaders(userA, "UserA_Headers.txt")
        elif choice == 1:  # User B selected
            self.saveHeaders(userB, "UserB_Headers.txt")

    def saveHeaders(self, user_dict, default_filename):
        # Save the headers to a specified file
        fileChooser = JFileChooser()
        fileChooser.setSelectedFile(java.io.File(
            default_filename))  # Set a default filename
        returnVal = fileChooser.showSaveDialog(self.mainPanel)
        if returnVal == JFileChooser.APPROVE_OPTION:
            selectedFile = fileChooser.getSelectedFile()
            try:
                # Write headers to the selected file
                with open(selectedFile.getAbsolutePath(), 'w') as file:
                    for key, value in user_dict.items():
                        file.write('"{}": "{}",\n'.format(key, value))
                JOptionPane.showMessageDialog(
                    self.mainPanel, "Data saved successfully to {}".format(selectedFile.getName()))
            except Exception as ex:
                JOptionPane.showMessageDialog(
                    self.mainPanel, "Error saving file: " + str(ex))

    def loadClick(self, event):
        # Handle loading user data from a file
        options = ["User A", "User B"]
        choice = JOptionPane.showOptionDialog(
            self.mainPanel,
            "Select the user to load headers:",
            "Load Headers",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.INFORMATION_MESSAGE,
            None,
            options,
            options[0]
        )
        if choice == 0:  # User A selected
            self.loadHeaders(userA, self._userATable)
        elif choice == 1:  # User B selected
            self.loadHeaders(userB, self._userBTable)

    def loadHeaders(self, user_dict, table):
        # Load headers from a specified file
        fileChooser = JFileChooser()
        returnVal = fileChooser.showOpenDialog(self.mainPanel)
        if returnVal == JFileChooser.APPROVE_OPTION:
            selectedFile = fileChooser.getSelectedFile()
            try:
                user_dict.clear()  # Clear existing headers before loading
                with open(selectedFile.getAbsolutePath(), 'r') as file:
                    for line in file:
                        try:
                            if ":" in line:
                                # Split line into header name and value
                                headerName, headerValue = line.split(":", 1)
                                user_dict[headerName.strip().replace('"', '')] = headerValue.strip().replace(
                                    ',', '').replace('"', '')
                        except Exception:
                            continue
                table.redrawTable()  # Refresh the UI table to show loaded headers
                JOptionPane.showMessageDialog(
                    self.mainPanel, "Data loaded successfully from {}".format(selectedFile.getName()))
            except Exception as ex:
                JOptionPane.showMessageDialog(
                    self.mainPanel, "Error loading file: " + str(ex))

    def clearClick(self, event):
        # Handle clearing user data
        options = ["User A", "User B"]
        choice = JOptionPane.showOptionDialog(
            self.mainPanel,
            "Select the user data to clear:",
            "Clear Data",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.INFORMATION_MESSAGE,
            None,
            options,
            options[0]
        )
        if choice == 0:  # User A selected
            userA.clear()
            self._dbA.updateData(userA)  # Update data model
            self._userATable.redrawTable()  # Refresh UI
            JOptionPane.showMessageDialog(
                self.mainPanel, "User A data cleared.")
        elif choice == 1:  # User B selected
            userB.clear()  # Clear User B's data
            self._dbB.updateData(userB)  # Update data model
            self._userBTable.redrawTable()  # Refresh UI
            JOptionPane.showMessageDialog(
                self.mainPanel, "User B data cleared.")

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


# Helper Classes

class MatrixDB():
    def __init__(self, user_dict):
        self.STATIC_USER_TABLE_COLUMN_COUNT = 2
        self.user_dict = user_dict

    def updateData(self, user_dict):
        self.user_dict = user_dict  # Update the underlying user dictionary


class UserEntry:
    def __init__(self, headerName, headerValue):
        self._headerName = headerName
        self._headerValue = headerValue


class UserTableModel(AbstractTableModel):
    def __init__(self, db):
        self._db = db

    def getRowCount(self):
        return len(self._db.user_dict)  # Returns the number of headers

    def getColumnCount(self):
        return self._db.STATIC_USER_TABLE_COLUMN_COUNT  # Fixed column count

    def getValueAt(self, rowIndex, columnIndex):
        key = list(self._db.user_dict.keys())[rowIndex]
        # Return header name or value
        return key if columnIndex == 0 else self._db.user_dict[key]

    def getColumnName(self, columnIndex):
        return "Header Name" if columnIndex == 0 else "Header Value"  # Column names


class UserTable(JTable):
    def __init__(self, model):
        self.setModel(model)  # Set data model for the table

    def redrawTable(self):
        self.getModel().fireTableDataChanged()  # Refresh table display
