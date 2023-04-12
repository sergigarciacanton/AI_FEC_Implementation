#!/usr/bin/env python
# liuw
# Nasty hack to raise exception for other threads

import ctypes  # Calm down, this has become standard library since 2.5
import threading
import time

NULL = 0


def ctype_async_raise(thread_id, exception):
    ret = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread_id), ctypes.py_object(exception))
    # ref: http://docs.python.org/c-api/init.html#PyThreadState_SetAsyncExc
    if ret == 0:
        raise ValueError("Invalid thread ID")
    elif ret > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, NULL)
        raise SystemError("PyThreadState_SetAsyncExc failed")
    print("Successfully set asynchronized exception for ", thread_id)


def f():
    try:
        while True:
            time.sleep(1)
    except SystemExit:
        pass
    finally:
        print("Exited")


t = threading.Thread(target=f)
t.start()
print("Thread started")
print(t.is_alive())
time.sleep(5)
ctype_async_raise(t.ident, SystemExit)
t.join()
print(t.is_alive())
