# -*- coding: utf-8 -*-

import os
import json
import inspect
import re
import time
import random
import sys
import codecs

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IHttpRequestResponse

from javax.swing import JMenuItem, JOptionPane
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.util import ArrayList

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        writer_out = codecs.getwriter('utf-8')(callbacks.getStdout())
        writer_out.errors = 'replace'
        sys.stdout = writer_out

        writer_err = codecs.getwriter('utf-8')(callbacks.getStderr())
        writer_err.errors = 'replace'
        sys.stderr = writer_err

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Invoker Extension")

        print("=====================================================")
        print(" Invoker - by Paweł Zdunek (AFINE)")
        print("=====================================================")

        self.base_path = self.determineBasePath()

        self.global_raw_folder_template = "/tmp/{{HOST}}"

        self.commands_config = []
        self.authenticatedHeaders = None

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
    #
    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        tool_flag = invocation.getToolFlag()

        if tool_flag == self._callbacks.TOOL_REPEATER:
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

        user_headers = []
        for h in headers[1:]:
            if h.lower().startswith("content-length"):
                continue
            user_headers.append(h)

        self.authenticatedHeaders = user_headers
        self.showInfoDialog("Authenticated Request set.\nThese headers will be used for future requests in Targets tab.")

    #
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

        try:
            cb = Toolkit.getDefaultToolkit().getSystemClipboard()
            sel = StringSelection(cmd)
            cb.setContents(sel, None)
        except:
            pass

        self.showInfoDialog("Command copied:\n\n" + cmd)
        print("[Invoker] Repeater single command:\n" + cmd)

    #
    #
    def onMenuClickTargets(self, invocation, config_entry):
        messages = invocation.getSelectedMessages()
        if not messages or len(messages) == 0:
            return

        if len(messages) == 1:
            single = messages[0]
            if single is not None and single.getRequest() is not None:
                req_info = self._helpers.analyzeRequest(single)
                if req_info is not None:
                    url_obj = req_info.getUrl()
                    if url_obj is not None:
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
            if ihrr is None:
                continue
            if ihrr.getRequest() is None:
                continue

            try:
                result = self.buildCommandForOneRequest(ihrr, config_entry, from_target=True, warnings=warnings)
            except Exception as ex:
                warnings.append("Error building command for one request: %s" % str(ex))
                continue

            if not result:
                continue

            (cmd, ffuf_url) = result

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
            self.showWarnDialog(msg)
            return

        first_valid = messages[0]
        fi_reqinfo = self._helpers.analyzeRequest(first_valid)
        fi_host = fi_reqinfo.getUrl().getHost()

        final_global_folder = self.resolveGlobalFolder(fi_host)
        if not os.path.exists(final_global_folder):
            os.makedirs(final_global_folder)

        timestamp = int(time.time())
        filename = "invoker_commands_%d.sh" % timestamp
        full_path = os.path.join(final_global_folder, filename)

        file_ok = True
        try:
            import codecs
            with codecs.open(full_path, "w", "utf-8", errors="replace") as f:
                for c in commands:
                    f.write(c)
                    f.write(u"\n")
        except Exception as e:
            file_ok = False
            warnings.append("Error writing commands file: %s" % str(e))

        copied_to_clipboard = False
        if file_ok:
            try:
                cb = Toolkit.getDefaultToolkit().getSystemClipboard()
                sel = StringSelection(full_path)
                cb.setContents(sel, None)
                copied_to_clipboard = True
            except Exception as e:
                warnings.append("Error copying path to clipboard: %s" % str(e))

        msg = "Generated %d commands." % len(commands)
        if file_ok:
            msg += "\nSaved to %s" % full_path
        else:
            msg += "\n(No output file was created.)"

        if copied_to_clipboard:
            msg += "\n(Path copied to clipboard.)"
        else:
            msg += "\n(Path NOT copied to clipboard.)"

        if warnings:
            msg += "\n\nWarnings:\n- " + "\n- ".join(warnings)

        self.showInfoDialog(msg)
        print("[Invoker] Targets multi commands =>", full_path if file_ok else "(no file)")

    #
    #
    def buildCommandForOneRequest(self, ihrr, config_entry, from_target, warnings):
        if ihrr is None or ihrr.getRequest() is None:
            return None

        req_info = self._helpers.analyzeRequest(ihrr)
        if req_info is None:
            return None
        url_obj = req_info.getUrl()
        if url_obj is None:
            return None

        url_str = self.safeUrlToString(url_obj)

        method = req_info.getMethod()

        try:
            method = method.encode("utf-8", "replace")
            method = method.decode("utf-8", "replace")
        except:
            method = "UNKNOWN_METHOD"

        body_offset = req_info.getBodyOffset()
        all_bytes = ihrr.getRequest()
        body = all_bytes[body_offset:]

        try:
            body_str = self._helpers.bytesToString(body)
        except:
            body_str = self.hexFallback(body)

        body_str_escaped = body_str.replace('"', '\\"')

        orig_headers = req_info.getHeaders()
        user_headers = []
        for h in orig_headers[1:]:
            if h.lower().startswith("content-length"):
                continue
            user_headers.append(h)

        if from_target and self.authenticatedHeaders is not None:
            user_headers = self.authenticatedHeaders
        elif from_target and self.authenticatedHeaders is None and warnings is not None:
            warnings.append("No Auth set => used original headers for " + url_str)

        tool = config_entry.get("tool", "").lower()
        (method_switch, force_ssl_flag, skipTool) = self.applySmartLogic(tool, method, url_obj)
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

        ffuf_url = None
        if tool == "ffuf":
            if "{{FFUF_URL}}" in cmd:
                fu = self.makeFfufUrl(url_obj)
                cmd = cmd.replace("{{FFUF_URL}}", fu)
                ffuf_url = fu

        if "{{OUTPUT}}" in cmd:
            out_path = self.makeOutputFilename(tool, url_obj)
            cmd = cmd.replace("{{OUTPUT}}", out_path)

        if "{{RAW_PATH}}" in cmd:
            raw_path = self.saveRawRequest(ihrr, from_target, user_headers)
            cmd = cmd.replace("{{RAW_PATH}}", raw_path)

        return (cmd, ffuf_url)

    #
    #
    def safeUrlToString(self, url_obj):
        if not url_obj:
            return "invalid_url"

        try:
            raw_java_str = url_obj.toString()
            utf = raw_java_str.encode("utf-8", "replace")
            safe_str = utf.decode("utf-8", "replace")
            return safe_str
        except:
            return "invalid_url"

    #
    #
    def hexFallback(self, data_bytes):
        escaped = []
        for b in data_bytes:
            val = b
            if val < 0:
                val += 256
            escaped.append("\\x%02x" % val)
        return "".join(escaped)

    def makeOutputFilename(self, tool, url_obj):
        final_folder = self.resolveGlobalFolder(url_obj.getHost())
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

    def saveRawRequest(self, ihrr, from_target, user_headers):
        req_info = self._helpers.analyzeRequest(ihrr)
        if req_info is None:
            return "/tmp/invoker_failed.req"
        url_obj = req_info.getUrl()
        if url_obj is None:
            return "/tmp/invoker_failed.req"

        host = url_obj.getHost()
        final_folder = self.resolveGlobalFolder(host)
        requests_folder = os.path.join(final_folder, "requests")

        try:
            if not os.path.exists(requests_folder):
                os.makedirs(requests_folder)

            timestamp = int(time.time())
            rnd = random.randint(1000,9999)
            filename = "invoker_%d_%d.req" % (timestamp, rnd)
            full_path = os.path.join(requests_folder, filename)

            req_bytes = ihrr.getRequest()
            if not from_target:
                with open(full_path, "wb") as f:
                    f.write(req_bytes)
            else:
                original_headers = req_info.getHeaders()
                if original_headers is None or len(original_headers) == 0:
                    return "/tmp/invoker_failed.req"

                start_line = original_headers[0]
                body_offset = req_info.getBodyOffset()
                body_bytes = req_bytes[body_offset:]

                lines = [start_line]
                for h in user_headers:
                    if h.lower().startswith("content-length"):
                        continue
                    lines.append(h)
                top = "\r\n".join(lines) + "\r\n\r\n"

                with open(full_path, "wb") as f:
                    f.write(top.encode("utf-8", "replace"))
                    f.write(body_bytes)

            return full_path
        except Exception as e:
            print("[InvokerExtension] Error saving raw request:", e)
            return "/tmp/invoker_failed.req"

    def resolveGlobalFolder(self, host):
        return self.global_raw_folder_template.replace("{{HOST}}", host)

    def applySmartLogic(self, tool, method, url_obj):
        method_switch = ""
        force_ssl_flag = ""
        skipTool = False

        is_https = (url_obj.getProtocol().lower() == "https")
        t = tool.lower()

        if t == "dosfiner":
            meth_up = method.upper()
            if meth_up == "GET":
                method_switch = "-g"
            elif meth_up == "POST":
                method_switch = "-p"
            else:
                method_switch = "-g"
            if is_https:
                force_ssl_flag = "-force-ssl"

        elif t == "sqlmap":
            if is_https:
                force_ssl_flag = "--force-ssl"

        elif t == "ffuf":
            if is_https:
                force_ssl_flag = "-ssl"

        elif t == "nuclei":
            if is_https:
                force_ssl_flag = "--force-ssl"

        elif t == "tplmap":
            pass

        return (method_switch, force_ssl_flag, skipTool)

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

    def showInfoDialog(self, msg):
        safe_msg = self.safeStringForDialog(msg)
        JOptionPane.showMessageDialog(
            None,
            safe_msg,
            "InvokerExtension",
            JOptionPane.INFORMATION_MESSAGE
        )

    def showWarnDialog(self, msg):
        safe_msg = self.safeStringForDialog(msg)
        JOptionPane.showMessageDialog(
            None,
            safe_msg,
            "InvokerExtension",
            JOptionPane.WARNING_MESSAGE
        )

    def safeStringForDialog(self, txt):
        """
        Konwertuje 'txt' do formatu UTF-8 z replace,
        a potem z powrotem do unicode – dzięki temu
        wszelkie trudne znaki zostaną zastąpione `?`.
        """
        try:
            if txt is None:
                return "None"
            if not isinstance(txt, basestring):
                txt = str(txt)
            tmp = txt.encode("utf-8", "replace")
            safe_txt = tmp.decode("utf-8", "replace")
            return safe_txt
        except:
            return "ConversionError"
