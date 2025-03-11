# -*- coding: utf-8 -*-

import os
import json
import inspect
import re
import time
import random

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IHttpRequestResponse

from javax.swing import JMenuItem, JOptionPane
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.util import ArrayList

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Invoker Extension")
        print("=====================================================")
        print(" DoS Finder - by Paweł Zdunek (AFINE)")
        print("=====================================================")

        self.base_path = self.determineBasePath()

        # Domyślnie, jeśli user nie ustawi nic:
        self.global_raw_folder_template = "/tmp/{{HOST}}"

        self.commands_config = []
        self.authenticatedHeaders = None  # do SetAsAuth

        self.loadConfigFromFile()
        callbacks.registerContextMenuFactory(self)
        return

    def determineBasePath(self):
        try:
            script_path = inspect.getfile(self.__class__)
            base = os.path.dirname(os.path.abspath(script_path))
            if base and os.path.exists(base):
                return base
        except:
            pass
        return os.getcwd()

    def loadConfigFromFile(self):
        json_path = os.path.join(self.base_path, "InvokerConfig.json")
        print("[InvokerExtension] Attempting to load config from:", json_path)

        try:
            with open(json_path, "r") as f:
                data = f.read()
            parsed = json.loads(data)

            if not isinstance(parsed, list):
                print("[InvokerExtension] JSON top-level not a list => no config loaded.")
                self.commands_config = []
                return

            # Jeśli pierwszy element ma "global_raw_folder"
            if len(parsed) > 0 and "global_raw_folder" in parsed[0]:
                self.global_raw_folder_template = parsed[0]["global_raw_folder"]
                self.commands_config = parsed[1:]
            else:
                self.commands_config = parsed

            print("[InvokerExtension] global_raw_folder_template =", self.global_raw_folder_template)
            print("[InvokerExtension] Number of tool entries:", len(self.commands_config))

        except Exception as e:
            print("[InvokerExtension] Could not load InvokerConfig.json:", e)
            self.commands_config = []

    #
    # IContextMenuFactory
    #
    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        tool_flag = invocation.getToolFlag()

        if tool_flag == self._callbacks.TOOL_REPEATER:
            # Add "Set as Authenticated Request"
            set_auth = JMenuItem("Set as Authenticated Request",
                actionPerformed=lambda x, inv=invocation: self.setAsAuthenticatedRequest(inv)
            )
            menu_items.add(set_auth)

            if len(self.commands_config) == 0:
                dummy = JMenuItem("[Invoker] No config entries found")
                dummy.setEnabled(False)
                menu_items.add(dummy)
            else:
                for entry in self.commands_config:
                    name = entry.get("name", "Unnamed")
                    menu_item = JMenuItem(
                        name,
                        actionPerformed=lambda x, e=entry, inv=invocation: self.onMenuClickRepeater(inv, e)
                    )
                    menu_items.add(menu_item)

        elif tool_flag == self._callbacks.TOOL_TARGET:
            if len(self.commands_config) == 0:
                dummy = JMenuItem("[Invoker] No config entries found")
                dummy.setEnabled(False)
                menu_items.add(dummy)
            else:
                for entry in self.commands_config:
                    name = entry.get("name", "Unnamed")
                    menu_item = JMenuItem(
                        name,
                        actionPerformed=lambda x, e=entry, inv=invocation: self.onMenuClickTargets(inv, e)
                    )
                    menu_items.add(menu_item)

        return menu_items

    def setAsAuthenticatedRequest(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        ihrr = messages[0]
        if not ihrr:
            return

        req_info = self._helpers.analyzeRequest(ihrr)
        headers = req_info.getHeaders()

        # omijamy Content-Length
        user_headers = []
        for h in headers[1:]:
            if h.lower().startswith("content-length"):
                continue
            user_headers.append(h)

        self.authenticatedHeaders = user_headers
        JOptionPane.showMessageDialog(None,
            "Authenticated Request set.\nThese headers will be used for future requests in Targets tab.",
            "InvokerExtension",
            JOptionPane.INFORMATION_MESSAGE
        )

    #
    # Repeater => single
    #
    def onMenuClickRepeater(self, invocation, config_entry):
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        ihrr = messages[0]
        if not ihrr:
            return

        result = self.buildCommandForOneRequest(ihrr, config_entry, from_target=False, warnings=None)
        if not result:
            return
        (cmd, ffuf_url) = result

        # copy to clipboard
        try:
            cb = Toolkit.getDefaultToolkit().getSystemClipboard()
            sel = StringSelection(cmd)
            cb.setContents(sel, None)
        except:
            pass

        JOptionPane.showMessageDialog(None,
            "Command copied:\n\n" + cmd,
            "InvokerExtension",
            JOptionPane.INFORMATION_MESSAGE
        )
        print("[Invoker] Repeater single command:\n" + cmd)

    #
    # Targets => multi => .sh
    #
    def onMenuClickTargets(self, invocation, config_entry):
        messages = invocation.getSelectedMessages()
        if not messages or len(messages) == 0:
            return

        # if user selected only 1 node with path = "/" => expand siteMap
        if len(messages) == 1:
            single = messages[0]
            req_info = self._helpers.analyzeRequest(single)
            url_obj = req_info.getUrl()
            path = url_obj.getPath()
            if path == "/" or path == "":
                host = url_obj.getHost()
                port = url_obj.getPort()
                protocol = url_obj.getProtocol()
                if port == -1:
                    prefix = "%s://%s" % (protocol, host)
                else:
                    prefix = "%s://%s:%d" % (protocol, host, port)
                site_msgs = self._callbacks.getSiteMap(prefix)
                if site_msgs:
                    messages = site_msgs

        commands = []
        warnings = []
        used_ffuf_urls = set()

        for ihrr in messages:
            result = self.buildCommandForOneRequest(ihrr, config_entry, from_target=True, warnings=warnings)
            if not result:
                continue
            (cmd, ffuf_url) = result

            # deduplicate ffuf
            if ffuf_url:
                if ffuf_url in used_ffuf_urls:
                    warnings.append("Skipping duplicate FFUF URL => %s" % ffuf_url)
                    continue
                used_ffuf_urls.add(ffuf_url)

            commands.append(cmd)

        if not commands:
            msg = "No commands were generated."
            if warnings:
                msg += "\n\nWarnings:\n- " + "\n- ".join(warnings)
            JOptionPane.showMessageDialog(
                None, msg, "InvokerExtension",
                JOptionPane.WARNING_MESSAGE
            )
            return

        # zapisz do pliku .sh w <global_raw_folder> (po zastepieniu {{HOST}})
        # Problem: w multi-requestach może być wiele hostów. Wybierzmy host 1szy? Albo 'multi'?
        # Dla prostoty: bierzemy host z 1 requestu
        first = messages[0]
        fi_reqinfo = self._helpers.analyzeRequest(first)
        fi_host = fi_reqinfo.getUrl().getHost()

        # Tworzymy final global folder
        final_global_folder = self.resolveGlobalFolder(fi_host)
        if not os.path.exists(final_global_folder):
            os.makedirs(final_global_folder)

        timestamp = int(time.time())
        filename = "invoker_commands_%d.sh" % timestamp
        full_path = os.path.join(final_global_folder, filename)

        try:
            with open(full_path, "w") as f:
                for c in commands:
                    f.write(c + "\n")

            # copy sciezke do schowka
            try:
                cb = Toolkit.getDefaultToolkit().getSystemClipboard()
                sel = StringSelection(full_path)
                cb.setContents(sel, None)
            except:
                pass

            msg = "Generated %d commands.\nSaved to %s" % (len(commands), full_path)
            if warnings:
                msg += "\n\nWarnings:\n- " + "\n- ".join(warnings)
            msg += "\n\n(Path copied to clipboard.)"

            JOptionPane.showMessageDialog(None,
                msg, "InvokerExtension",
                JOptionPane.INFORMATION_MESSAGE
            )
            print("[Invoker] Targets multi commands =>", full_path)

        except Exception as e:
            JOptionPane.showMessageDialog(None,
                "Error writing commands file:\n" + str(e),
                "InvokerExtension",
                JOptionPane.ERROR_MESSAGE
            )

    #
    # Główna metoda
    #
    def buildCommandForOneRequest(self, ihrr, config_entry, from_target, warnings):
        req_info = self._helpers.analyzeRequest(ihrr)
        method = req_info.getMethod()
        url_obj = req_info.getUrl()
        url_str = str(url_obj)

        body_offset = req_info.getBodyOffset()
        all_bytes = ihrr.getRequest()
        body = all_bytes[body_offset:]
        body_str = self._helpers.bytesToString(body)
        body_str_escaped = body_str.replace('"', '\\"')

        orig_headers = req_info.getHeaders()
        user_headers = []
        for h in orig_headers[1:]:
            if h.lower().startswith("content-length"):
                continue
            user_headers.append(h)

        if from_target and self.authenticatedHeaders is not None:
            user_headers = self.authenticatedHeaders
        elif from_target and self.authenticatedHeaders is None:
            if warnings is not None:
                warnings.append("No Auth set => used original headers for " + url_str)

        tool = config_entry.get("tool", "").lower()
        method_switch, force_ssl_flag, skipTool = self.applySmartLogic(tool, method, url_obj)
        if skipTool:
            if warnings is not None:
                warnings.append("%s skip => method=%s at %s" % (tool, method, url_str))
            return None

        headers_joined_escaped = "\\n".join(user_headers).replace('"', '\\"')

        cmd_tpl = config_entry.get("template", "")
        cmd = cmd_tpl.replace("{{METHOD}}", method)
        cmd = cmd.replace("{{METHOD_SWITCH}}", method_switch)
        cmd = cmd.replace("{{URL}}", url_str)
        cmd = cmd.replace("{{BODY}}", body_str_escaped)
        cmd = cmd.replace("{{HEADERS}}", headers_joined_escaped)
        cmd = cmd.replace("{{FORCE_SSL}}", force_ssl_flag)
        cmd = cmd.replace("{{PROXY_PORT}}", str(self.getProxyPort()))

        cmd = self.replaceHeadersMultiFlag(cmd, user_headers)

        # ffuf deduplik
        ffuf_url = None
        if tool == "ffuf":
            if "{{FFUF_URL}}" in cmd:
                fu = self.makeFfufUrl(url_obj)
                cmd = cmd.replace("{{FFUF_URL}}", fu)
                ffuf_url = fu

        # if w template jest {{OUTPUT}} => generujemy plik w results/
        if "{{OUTPUT}}" in cmd:
            out_path = self.makeOutputFilename(tool, url_obj)
            cmd = cmd.replace("{{OUTPUT}}", out_path)

        # if {{RAW_PATH}} => surowy request do requests/
        if "{{RAW_PATH}}" in cmd:
            raw_path = self.saveRawRequest(ihrr, from_target, user_headers)
            cmd = cmd.replace("{{RAW_PATH}}", raw_path)

        return (cmd, ffuf_url)

    #
    # Tworzy sciezke do zapisu wynikow:
    # finalGlobalFolder = self.resolveGlobalFolder(host)
    # -> finalGlobalFolder/results/<tool>_<host>_<pathSegment>_<timestamp>_<rnd>.json
    #
    def makeOutputFilename(self, tool, url_obj):
        final_folder = self.resolveGlobalFolder(url_obj.getHost())  # np /tmp/localhost
        results_folder = os.path.join(final_folder, "results")
        if not os.path.exists(results_folder):
            os.makedirs(results_folder)

        path = url_obj.getPath() or "/"
        seg = path.strip("/")
        if not seg:
            seg = "root"
        else:
            parts = seg.split("/")
            seg = parts[-1] if parts[-1] else "root"

        timestamp = int(time.time())
        rnd = random.randint(1000, 9999)

        filename = "%s_%s_%s_%d_%d.json" % (tool, url_obj.getHost(), seg, timestamp, rnd)
        return os.path.join(results_folder, filename)

    #
    # Zapis surowego requestu: <finalGlobalFolder>/requests/invoker_timestamp_rand.req
    #
    def saveRawRequest(self, ihrr, from_target, user_headers):
        req_info = self._helpers.analyzeRequest(ihrr)
        host = req_info.getUrl().getHost()
        final_folder = self.resolveGlobalFolder(host)
        requests_folder = os.path.join(final_folder, "requests")

        try:
            if not os.path.exists(requests_folder):
                os.makedirs(requests_folder)

            timestamp = int(time.time())
            rnd = random.randint(1000,9999)
            filename = "invoker_%d_%d.req" % (timestamp, rnd)
            full_path = os.path.join(requests_folder, filename)

            if not from_target:
                req_bytes = ihrr.getRequest()
                with open(full_path, "wb") as f:
                    f.write(req_bytes)
            else:
                # reconstruct with user_headers
                original_headers = req_info.getHeaders()
                start_line = original_headers[0]
                body_offset = req_info.getBodyOffset()
                all_bytes = ihrr.getRequest()
                body_bytes = all_bytes[body_offset:]

                lines = [start_line]
                for h in user_headers:
                    if h.lower().startswith("content-length"):
                        continue
                    lines.append(h)
                top = "\r\n".join(lines) + "\r\n\r\n"

                with open(full_path, "wb") as f:
                    f.write(top.encode("utf-8"))
                    f.write(body_bytes)

            return full_path
        except Exception as e:
            print("[InvokerExtension] Error saving raw request:", e)
            return "/tmp/invoker_failed.req"

    #
    # Zamienia w self.global_raw_folder_template np "/tmp/{{HOST}}"
    # na "/tmp/localhost" (jeśli host=localhost)
    #
    def resolveGlobalFolder(self, host):
        return self.global_raw_folder_template.replace("{{HOST}}", host)

    #
    # applySmartLogic -> dosfiner skip, etc.
    #
    def applySmartLogic(self, tool, method, url_obj):
        method_switch = ""
        force_ssl_flag = ""
        skipTool = False

        is_https = (url_obj.getProtocol().lower() == "https")

        if tool == "dosfiner":
            if method.upper() == "GET":
                method_switch = "-g"
            elif method.upper() == "POST":
                method_switch = "-p"
            else:
                skipTool = True
            if is_https:
                force_ssl_flag = "-force-ssl"

        elif tool == "sqlmap":
            if is_https:
                force_ssl_flag = "--force-ssl"

        elif tool == "ffuf":
            if is_https:
                force_ssl_flag = "-ssl"

        elif tool == "nuclei":
            if is_https:
                force_ssl_flag = "--force-ssl"

        elif tool == "tplmap":
            pass

        return (method_switch, force_ssl_flag, skipTool)

    #
    # Generuje URL do ffuf => wstawia /FUZZ
    #
    def makeFfufUrl(self, url_obj):
        protocol = url_obj.getProtocol()
        host = url_obj.getHost()
        port = url_obj.getPort()
        path = url_obj.getPath() or "/"

        if port == -1:
            base = "%s://%s" % (protocol, host)
        else:
            base = "%s://%s:%d" % (protocol, host, port)

        if path == "/" or not path:
            return base + "/FUZZ"

        idx = path.rfind("/")
        if idx == -1:
            return base + "/FUZZ"
        else:
            dir_part = path[:idx]
            if not dir_part.startswith("/"):
                dir_part = "/" + dir_part
            return base + dir_part + "/FUZZ"

    def replaceHeadersMultiFlag(self, cmd, headers_list):
        pattern = re.compile(r'{{HEADERS\[(.*?)\]}}')
        matches = pattern.findall(cmd)
        for match in matches:
            replacement = self.expandMultiFlagHeaders(headers_list, match)
            find_str = "{{HEADERS[%s]}}" % match
            cmd = cmd.replace(find_str, replacement)
        return cmd

    def expandMultiFlagHeaders(self, headers_list, prefix):
        parts = []
        for h in headers_list:
            safe_h = h.replace('"', '\\"')
            parts.append('%s "%s"' % (prefix, safe_h))
        return " ".join(parts)

    def getProxyPort(self):
        default_port = 8080
        try:
            listeners = self._callbacks.getProxyListeners()
            if listeners and len(listeners) > 0:
                for l in listeners:
                    if l.isRunning():
                        return l.getListenPort()
        except:
            pass
        return default_port
