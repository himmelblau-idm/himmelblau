#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright 2024 Siemens AG

# pylint: disable=missing-docstring,invalid-name

# Renable invalid-name check, it should only cover the module name
# pylint: enable=invalid-name

import argparse
import sys
import json
import struct
import uuid
import ctypes
import time
from signal import SIGINT
from threading import Thread, Lock
from gi.repository import GLib, Gio
from pydbus import SessionBus

# version is replaced on installation
LINUX_ENTRA_SSO_VERSION = ""

# the ssoUrl is a mandatory parameter when requesting a PRT SSO
# Cookie, but the correct value is not checked as of 30.05.2024
# by the authorization backend. By that, a static (fallback)
# value can be used, if no real value is provided.
SSO_URL_DEFAULT = "https://login.microsoftonline.com/"
EDGE_BROWSER_CLIENT_ID = "d7b530a4-7680-4c23-a8bf-c52c121d2e87"
BROKER_START_TIMEOUT = 5
# dbus start service reply codes
START_REPLY_SUCCESS = 1
START_REPLY_ALREADY_RUNNING = 2
# prctl constants
PR_SET_PDEATHSIG = 1


class NativeMessaging:
    @staticmethod
    def get_message():
        """
            Read a message from stdin and decode it.
        """
        raw_length = sys.stdin.buffer.read(4)
        if not raw_length:
            sys.exit(0)
        message_length = struct.unpack('@I', raw_length)[0]
        message = sys.stdin.buffer.read(message_length).decode('utf-8')
        return json.loads(message)

    @staticmethod
    def encode_message(message_content):
        """
            Encode a message for transmission, given its content
        """
        encoded_content = json.dumps(message_content, separators=(',', ':')) \
            .encode('utf-8')
        encoded_length = struct.pack('@I', len(encoded_content))
        return {'length': encoded_length, 'content': encoded_content}

    @staticmethod
    def send_message(encoded_message):
        """
            Send an encoded message to stdout
        """
        sys.stdout.buffer.write(encoded_message['length'])
        sys.stdout.buffer.write(encoded_message['content'])
        sys.stdout.buffer.flush()


class SsoMib:
    BROKER_NAME = 'com.microsoft.identity.broker1'
    BROKER_PATH = '/com/microsoft/identity/broker1'
    GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]

    def __init__(self, daemon=False):
        self._bus = SessionBus()
        self.broker = None
        self.session_id = uuid.uuid4()
        self._state_changed_cb = None
        if daemon:
            self._introspect_broker(fail_on_error=False)
            self._monitor_bus()

    def _introspect_broker(self, fail_on_error=True):
        timeout = time.time() + BROKER_START_TIMEOUT
        while not self.broker and time.time() < timeout:
            try:
                self.broker = self._bus.get(self.BROKER_NAME, self.BROKER_PATH)
                return
            except GLib.Error as err:
                # GDBus.Error:org.freedesktop.dbus.errors.UnknownObject:
                # Introspecting on non-existant object
                # See https://github.com/siemens/linux-entra-sso/issues/33
                if err.matches(Gio.io_error_quark(),
                               Gio.IOErrorEnum.DBUS_ERROR):
                    time.sleep(0.1)
                    continue
            if fail_on_error:
                raise RuntimeError("Could not start broker")

    def _monitor_bus(self):
        self._bus.subscribe(
            sender="org.freedesktop.DBus",
            object="/org/freedesktop/DBus",
            signal="NameOwnerChanged",
            arg0=self.BROKER_NAME,
            signal_fired=self._broker_state_changed)

    def _broker_state_changed(self, sender, object, iface, signal, params): \
            # pylint: disable=redefined-builtin,too-many-arguments
        _ = (sender, object, iface, signal)
        # params = (name, old_owner, new_owner)
        new_owner = params[2]
        if new_owner:
            self._introspect_broker()
        else:
            # we need to ensure that the next dbus call will
            # wait until the broker is fully initialized again
            self.broker = None
        if self._state_changed_cb:
            self._state_changed_cb(new_owner)

    def on_broker_state_changed(self, callback):
        """
            Register a callback to be called when the broker state changes.
            The callback should accept a single boolean argument, indicating
            if the broker is online or not.
        """
        self._state_changed_cb = callback

    @staticmethod
    def _get_auth_parameters(account, scopes):
        return {
            'account': account,
            'additionalQueryParametersForAuthorization': {},
            'authority': 'https://login.microsoftonline.com/common',
            'authorizationType': 8,  # OAUTH2
            'clientId': EDGE_BROWSER_CLIENT_ID,
            'redirectUri': 'https://login.microsoftonline.com'
                           '/common/oauth2/nativeclient',
            'requestedScopes': scopes,
            'username': account['username'],
        }

    def get_accounts(self):
        self._introspect_broker()
        context = {
            'clientId': EDGE_BROWSER_CLIENT_ID,
            'redirectUri': str(self.session_id)
        }
        resp = self.broker.getAccounts('0.0',
                                       str(self.session_id),
                                       json.dumps(context))
        return json.loads(resp)

    def acquire_prt_sso_cookie(self, account, sso_url, scopes=GRAPH_SCOPES): \
            # pylint: disable=dangerous-default-value
        self._introspect_broker()
        request = {
            'account': account,
            'authParameters': SsoMib._get_auth_parameters(account, scopes),
            'ssoUrl': sso_url
        }
        token = json.loads(self.broker.acquirePrtSsoCookie(
            '0.0', str(self.session_id), json.dumps(request)))
        return token

    def acquire_token_silently(self, account, scopes=GRAPH_SCOPES): \
            # pylint: disable=dangerous-default-value
        self._introspect_broker()
        request = {
            'account': account,
            'authParameters': SsoMib._get_auth_parameters(account, scopes),
        }
        token = json.loads(self.broker.acquireTokenSilently(
            '0.0', str(self.session_id), json.dumps(request)))
        return token

    def get_broker_version(self):
        self._introspect_broker()
        params = json.dumps({"msalCppVersion": LINUX_ENTRA_SSO_VERSION})
        resp = json.loads(
            self.broker.getLinuxBrokerVersion('0.0',
                                              str(self.session_id),
                                              params))
        resp["native"] = LINUX_ENTRA_SSO_VERSION
        return resp


def run_as_native_messaging():
    iomutex = Lock()
    no_broker = {'error': 'Broker not available'}

    def respond(command, message):
        NativeMessaging.send_message(
            NativeMessaging.encode_message(
                {"command": command, "message": message}))

    def notify_state_change(online):
        with iomutex:
            respond("brokerStateChanged", 'online' if online else 'offline')

    def handle_command(cmd, received_message):
        if cmd == "acquirePrtSsoCookie":
            account = received_message['account']
            sso_url = received_message['ssoUrl'] or SSO_URL_DEFAULT
            token = ssomib.acquire_prt_sso_cookie(account, sso_url)
            respond(cmd, token)
        elif cmd == "acquireTokenSilently":
            account = received_message['account']
            scopes = received_message.get('scopes') or ssomib.GRAPH_SCOPES
            token = ssomib.acquire_token_silently(account, scopes)
            respond(cmd, token)
        elif cmd == "getAccounts":
            respond(cmd, ssomib.get_accounts())
        elif cmd == "getVersion":
            respond(cmd, ssomib.get_broker_version())

    def run_dbus_monitor():
        # inform other side about initial state
        notify_state_change(bool(ssomib.broker))
        loop = GLib.MainLoop()
        loop.run()

    def register_terminate_with_parent():
        libc = ctypes.CDLL("libc.so.6")
        libc.prctl(PR_SET_PDEATHSIG, SIGINT, 0, 0, 0)

    print("Running as native messaging instance.", file=sys.stderr)
    print("For interactive mode, start with --interactive", file=sys.stderr)

    # on chrome and chromium, the parent process does not reliably
    # terminate the process when the parent process is killed.
    register_terminate_with_parent()

    ssomib = SsoMib(daemon=True)
    ssomib.on_broker_state_changed(notify_state_change)
    monitor = Thread(target=run_dbus_monitor)
    monitor.start()
    while True:
        received_message = NativeMessaging.get_message()
        with iomutex:
            cmd = received_message['command']
            try:
                handle_command(cmd, received_message)
            except Exception:  # pylint: disable=broad-except
                respond(cmd, no_broker)


def run_interactive():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="run in interactive mode")
    parser.add_argument("-a", "--account", type=int, default=0,
                        help="account index to use for operations")
    parser.add_argument("-s", "--ssoUrl", default=SSO_URL_DEFAULT,
                        help="ssoUrl part of SSO PRT cookie request")
    parser.add_argument("command", choices=["getAccounts",
                                            "getVersion",
                                            "acquirePrtSsoCookie",
                                            "acquireTokenSilently",
                                            "monitor"])
    args = parser.parse_args()

    monitor_mode = args.command == "monitor"
    ssomib = SsoMib(daemon=monitor_mode)
    if monitor_mode:
        print("Monitoring D-Bus for broker availability.")
        ssomib.on_broker_state_changed(
            lambda online: print(f"{ssomib.BROKER_NAME} is now "
                                 f"{'online' if online else 'offline'}."))
        GLib.MainLoop().run()
        return

    accounts = ssomib.get_accounts()
    if args.command == 'getAccounts':
        json.dump(accounts, indent=2, fp=sys.stdout)
    elif args.command == 'getVersion':
        json.dump(ssomib.get_broker_version(), indent=2, fp=sys.stdout)
    elif args.command == "acquirePrtSsoCookie":
        account = accounts['accounts'][args.account]
        cookie = ssomib.acquire_prt_sso_cookie(account, args.ssoUrl)
        json.dump(cookie, indent=2, fp=sys.stdout)
    elif args.command == "acquireTokenSilently":
        account = accounts['accounts'][args.account]
        token = ssomib.acquire_token_silently(account)
        json.dump(token, indent=2, fp=sys.stdout)
    # add newline
    print()


if __name__ == '__main__':
    if '--interactive' in sys.argv or '-i' in sys.argv:
        run_interactive()
    else:
        run_as_native_messaging()
