import time
from threading import Lock

class Counter:
    def __init__(self):
        self.total = 0
    
    def add(self):
        self.total += 1

class IntervalCounter:
    def __init__(self, interval=60):
        self.interval = interval
        self.total = 0
        self.t = []
        self.add_lock = Lock()
    
    def add(self):
        with self.add_lock:
            self.total += 1
            self.t.append(time.time())
    
    def cpm(self):
        with self.add_lock:
            ct = time.time()
            self.t = list(filter(
                lambda x: (ct-x) <= self.interval,
                self.t
            ))
            return len(self.t)