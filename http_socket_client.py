import json
import requests
import time
from threading import Thread


class HSocket:
    """
    Client HSocket that communicates with the remote server HSocket
    """

    def __init__(self, host, auto_connect=True):  # type: (str, bool) -> None
        """
        Initializes the HSocket
        :param host: the host server URL (eg. if HSocket server is running on https://example.com/hsocket/
         then pass as host just "https://example.com")
        :param auto_connect: if set to True, immediately performs a connection to the host
        """
        self.host = host
        self._listeners = {}  # event name: function to call upon firing of the event

        self.__thread = None  # background thread for communicating with server
        self.connected = False  # indicated if the connection with the server is stable
        self.__connectedFired = False  # when listener for connected is not defined yet, it will be fired right after
        # definition if this is still False
        self._connecting = False  # indicates if we are at least connecting to the server
        self.sid = None  # local socket's id from server

        self._last_message_time = time.time()  # time of last message we got from the server
        self._fetch_msg_max_time = 10.0  # maximum time between fetching new messages from the server

        if auto_connect:
            self.connect()

    def connect(self):  # type: () -> None
        """
        Performs a connection to the server
        Fires 'connect' event upon successful connection
        :return: None
        """
        if self._connecting:
            return

        self._connecting = True

        class HSocketRecevierThread(Thread):
            """
            Thread that handles messages from the server
            """
            # noinspection PyMethodParameters
            def run(__):
                while self._connecting:  # as long as we are at least connecting to the server, fetch new messages
                    msg = self._get_message()
                    if (msg is None or msg.get('action', '') == 'disconnect') and self.connected:
                        # there was an error in communication or we are ordered to disconnect for now
                        self.disconnect(reconnect=True)  # disconnect for now, but retry later
                    elif msg is None:  # invalid message. Skip.
                        continue
                    elif msg.get('action', '') == 'connect':  # server processed our request and had decided to connect
                        # us. Accept a new socket ID from the server and run "connect" event
                        self.sid = msg['sid']
                        self.connected = True
                        self._run_listener('connect')
                    elif msg.get('action', '') == 'event':  # server is firing an event on us
                        # run the appropriate listener
                        self._run_listener(msg['name'], msg['data'])
                    elif msg.get('action', '') == 'set_max_msg_interval':  # server orders us to set a new maximum time
                        # between asking for new messages
                        self.set_retry_interval(float(msg['data']))

        # start the background communication thread
        self.__thread = HSocketRecevierThread()
        self.__thread.start()

    def disconnect(self, reconnect=False):  # type: (bool) -> None
        """
        Disconnect from the server
        :param reconnect: if set to True then after 30 seconds we will try to reconnect to the server
        :return: None
        """
        if not self._connecting:
            return

        # reset everything
        self.__thread = None
        self._connecting = False
        self.__connectedFired = False
        self.sid = None

        if self.connected:
            # if we are connected, inform the server about our disconnection
            try:
                requests.post(self.host + '/hsocket/', params={'sid': self.sid}, data={'action': 'disconnect'},
                              timeout=5)
            except requests.exceptions.ConnectionError or requests.exceptions.ConnectTimeout:
                pass
            except requests.exceptions.ReadTimeout:
                pass
            self.connected = False
            self._run_listener('disconnect')

        if reconnect:
            # if enabled, run the reconnection countdown in background
            def f_reconnect():
                time.sleep(30)
                self.connect()

            AsyncExecuter(f_reconnect).start()

    def on(self, event_name, func):  # type: (str, "function") -> None
        """
        Sets a new listener for an event
        :param event_name: name of the event that the listener shall listen for
        :param func: function fired upon calling of this event. Calls are performed like func(event_data)
        :return: None
        """
        item = self._listeners.get(event_name, [])
        item.append(func)
        self._listeners[event_name] = item

        if event_name == 'connect' and self.connected and not self.__connectedFired:
            self._run_listener(event_name)

    def emit(self, event_name, data=None):  # type: (str, any) -> None
        """
        Fire an event with specified data
        :param event_name: Name of the event to fire on the server
        :param data: data passed to the fired function
        :return: None
        """
        if not self.connected:
            return
        try:
            requests.post(self.host + '/hsocket/', params={'sid': self.sid}, data={'action': 'event',
                                                                                   'name': event_name,
                                                                                   'data': data})
        except requests.exceptions.ConnectionError:
            self.disconnect(reconnect=True)

    def set_retry_interval(self, interval):  # type: (float) -> None
        """
        Sets the maximum time in seconds before asking the server for new messages
        :param interval: maximum time in seconds before asking the server for new messages
        :return: None
        """
        self._fetch_msg_max_time = interval

    def _get_message(self):  # type: () -> dict or None
        """
        Waits until the message from server for this client is available or some error occurs and then returns
        the fetched message or None on fail
        :return: fetched message from the server or None on connection fail
        """
        try:
            while True:
                request = requests.get(self.host + '/hsocket/', params=None if self.sid is None else {'sid': self.sid},
                                       timeout=10)
                if request.status_code not in [200, 404]:
                    self.disconnect(reconnect=True)
                    return
                data = request.json()

                if data.get('action', '') != 'retry':  # if the message was a real message, save the time
                    # we have gathered it
                    if data.get('action', '') != 'set_max_msg_interval':
                        self._last_message_time = time.time()
                    break
                time.sleep(min(self._fetch_msg_max_time, max(1.0, time.time() - self._last_message_time)))
            return data
        except requests.exceptions.ConnectionError:
            self.disconnect(reconnect=True)
        except json.decoder.JSONDecodeError:
            raise HSocketException("This is not a http-socket server")
        except requests.exceptions.Timeout:
            pass

    def _run_listener(self, event_name, data=None):  # type: (str, any) -> None
        """
        Runs asynchronously all listeners for specified event
        :param event_name: name of the event listeners to run
        :param data: data to pass to the listening functions
        :return: None
        """
        if event_name == 'connect':
            self.__connectedFired = True
        for listener in self._listeners.get(event_name, []):
            AsyncExecuter(listener, data).start()


class AsyncExecuter(Thread):
    """
    Executes a function asynchronously
    """

    def __init__(self, func, data=None):  # type: ("function", any) -> None
        """
        Initializes the data for asynchronous execution.
        The execution itself must be then started by using .start()
        :param func: function to execute
        :param data: data passed to the executed function
        """
        Thread.__init__(self)
        self.func = func
        self.data = data

    def run(self):
        self.func() if self.data is None else self.func(self.data)


class HSocketException(Exception):
    pass


# If run directly, perform a quick test
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
