import json
import time
from threading import Thread

import requests


class HSocket:

    def __init__(self, host, auto_connect=True):
        self.host = host
        self._listeners = {}

        self.__thread = None
        self.connected = False
        self.__connectedFired = False
        self._connecting = False
        self.sid = None

        self._last_message_time = time.time()

        if auto_connect:
            self.connect()

    def connect(self):
        if self._connecting:
            return

        self._connecting = True

        class HSocketRecevierThread(Thread):
            # noinspection PyMethodParameters
            def run(__):
                while self._connecting:
                    msg = self._get_message()
                    if (msg is None or msg.get('action', '') == 'disconnect') and self.connected:
                        self.disconnect(reconnect=True)
                    elif msg is None:
                        continue
                    elif msg.get('action', '') == 'connect':
                        self.sid = msg['sid']
                        self.connected = True
                        self._run_listener('connect')
                    elif msg.get('action', '') == 'event':
                        self._run_listener(msg['name'], msg['data'])

        self.__thread = HSocketRecevierThread()
        self.__thread.start()

    def disconnect(self, reconnect=False):
        if not self._connecting:
            return
        self.__thread = None
        self._connecting = False
        self.__connectedFired = False
        self.sid = None

        if self.connected:
            try:
                requests.post(self.host + '/hsocket/', params={'sid': self.sid}, data={'action': 'disconnect'},
                              timeout=5)
            except requests.exceptions.ConnectionError or requests.exceptions.ConnectTimeout \
                   or requests.exceptions.ReadTimeout:
                pass
            self.connected = False
            self._run_listener('disconnect')

        if reconnect:
            def f_reconnect():
                time.sleep(30)
                self.connect()

            AsyncExecuter(f_reconnect).start()

    def on(self, event_name: str, func):
        item = self._listeners.get(event_name, [])
        item.append(func)
        self._listeners[event_name] = item

        if event_name == 'connect' and self.connected and not self.__connectedFired:
            self._run_listener(event_name)

    def emit(self, event_name: str, data=None):
        if not self.connected:
            return
        requests.post(self.host + '/hsocket/', params={'sid': self.sid}, data={'action': 'event', 'name': event_name,
                                                                               'data': data})

    def _get_message(self) -> dict or None:
        try:
            while True:
                request = requests.get(self.host + '/hsocket/', params=None if self.sid is None else {'sid': self.sid},
                                       timeout=10)
                if request.status_code not in [200, 404]:
                    self.disconnect(reconnect=True)
                    return
                data = request.json()
                if data['action'] != 'retry':
                    self._last_message_time = time.time()
                    break
                time.sleep(max(10.0, max(1.0, time.time() - self._last_message_time)))
            return data
        except requests.exceptions.ConnectionError:
            self.disconnect(reconnect=True)
        except json.decoder.JSONDecodeError:
            raise HSocketException("This is not a http-socket server")
        except requests.exceptions.Timeout:
            pass

    def _run_listener(self, event_name, data=None):
        if event_name == 'connect':
            self.__connectedFired = True
        for listener in self._listeners.get(event_name, []):
            AsyncExecuter(listener, data).start()


class AsyncExecuter(Thread):
    def __init__(self, func, data=None):
        Thread.__init__(self)
        self.func = func
        self.data = data

    def run(self):
        self.func() if self.data is None else self.func(self.data)


class HSocketException(Exception):
    pass


if __name__ == '__main__':
    sock = HSocket('http://127.0.0.1:5000')


    def connect():
        print('Connected')


    def disconnect():
        print('Disconnected')


    def hello(msg):
        print('Got:', msg)
        sock.emit('helloBack', 'You too, sir')


    sock.on('hello', hello)
    sock.on('connect', connect)
    sock.on('disconnect', disconnect)
