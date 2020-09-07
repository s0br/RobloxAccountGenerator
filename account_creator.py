## Roblox account generator /w gametype-1 funcaptcha solver
## twitter.com/h0nde
## 2020-09-07

## Please include proper credits if you're gonna use my funcaptcha module
## in a project of yours. Thank you.

from funcaptcha import FunCaptchaSession, Proxy, BadGameTypeOrVariant, BannedProxy
from fingerprint import Fingerprint, Window
from threading import Thread, Lock
from queue import Queue
from counter import Counter, IntervalCounter
import itertools
import random
import imageutil
import pickle
import time
import os
import secrets
import exrex
import requests
import ctypes
import yaml
if not os.path.exists("solver-db"):
    os.mkdir("solver-db")
if not os.path.exists("logs"):
    os.mkdir("logs")

## Load variables from config file
with open("config.yaml") as f:
    config = yaml.safe_load(f)
    hash_length = config["solver"]["hash_length"]
    hash_method = imageutil.methods[config["solver"]["hash_method"]]
    masking = config["solver"]["mask"]
    solver_count = config["threads"]["solver"]
    resubmitter_count = config["threads"]["resubmitter"]
    thread_count = config["threads"]["main"]
    user_agent = config["misc"]["user_agent"]

    un_gen = lambda: exrex.getone(config["generator"]["username"], limit=20)
    pw_gen = lambda: exrex.getone(config["generator"]["password"], limit=50)
    
bheaders = {
    "User-Agent": user_agent,
    "Origin": "https://www.roblox.com",
    "Referer": "https://www.roblox.com/account/signupredir"
}

## counters
created_counter = IntervalCounter()
solver_success_counter = Counter()
solver_failure_counter = Counter()

## solver variables
solved_queue = Queue()
resubmit_queue = Queue()
appear = {}
cache = {}

## Attempt to load database files into memory
try:
    with open("solver-db/appear.p", "rb") as f:
        appear = pickle.load(f)
    with open("solver-db/cache.p", "rb") as f:
        cache = pickle.load(f)
except: pass

## Stuff you can easily mess around with
wlock = Lock()
def account_callback(account):
    print("Created account:", account)
    created_counter.add()
    with wlock:
        with open("logs/cookies.txt", "a", encoding="UTF-8", errors="ignore") as f:
            f.write("%s\n" % account.cookie)

        with open("logs/combos_cookies.txt", "a", encoding="UTF-8", errors="ignore") as f:
            f.write("%s:%s:%s\n" % (
                account.username,
                account.password,
                account.safe_cookie()
            ))

def gen_username():
    un = ""
    while not un or un.startswith("_") or un.endswith("_") \
        or un.count("_") > 1 or len(un) < 4 or un.isdigit():
        un = un_gen()
    return un

def gen_password():
    return pw_gen()

## Modify proxy class to add support for storing xsrf tokens
class Proxy(Proxy):
    def __init__(self, proxy):
        self.xsrf_token = None
        super().__init__(proxy, "http")

## Load proxies into memory
with open("proxies.txt") as f:
    proxies = list(map(Proxy, f.read().splitlines()))
    proxies = itertools.cycle(proxies)

## Solver functions and workers
def get_identity():
    window = Window("Roblox", "https://www.roblox.com/account/signupredir")
    fp = Fingerprint(
        user_agent=user_agent,
        protochain_hash="5d76839801bc5904a4f12f1731a7b6d1",
        sec_fetch=True,
        content_type_value="application/x-www-form-urlencoded; charset=UTF-8",
        accept_language_value="en-US,en;q=0.9",
        jsbd_gen=lambda w: dict(HL=random.randint(1,5), NCE=True, DT=w.title, NWD="undefined", DA=None, DR=None, DMT=random.randint(1,40), DO=None, DOT=random.randint(30,50)),
        DNT="unknown",
        L="en-US",
        D=24,
        PR=1,
        S="1920,1080",
        AS="1920,1040",
        SS=True,
        LS=True,
        IDB=True,
        B=False,
        ODB=True,
        CPUC="unknown",
        PK="Win32",
        JSF="Arial,Arial Black,Arial Narrow,Book Antiqua,Bookman Old Style,Calibri,Cambria,Cambria Math,Century,Century Gothic,Century Schoolbook,Comic Sans MS,Consolas,Courier,Courier New,Garamond,Georgia,Helvetica,Impact,Lucida Bright,Lucida Calligraphy,Lucida Console,Lucida Fax,Lucida Handwriting,Lucida Sans,Lucida Sans Typewriter,Lucida Sans Unicode,Microsoft Sans Serif,Monotype Corsiva,MS Gothic,MS PGothic,MS Reference Sans Serif,MS Sans Serif,MS Serif,Palatino Linotype,Segoe Print,Segoe Script,Segoe UI,Segoe UI Light,Segoe UI Semibold,Segoe UI Symbol,Tahoma,Times,Times New Roman,Trebuchet MS,Verdana,Wingdings,Wingdings 2,Wingdings 3",
        P="Chrome PDF Plugin,Chrome PDF Viewer,Native Client",
        T="0,false,false",
        H="8",
        SWF=False
    )
    return fp, window

def get_session():
    fp, window = get_identity()
    fcs = FunCaptchaSession(
        public_key="A2A14B1D-1AF3-C791-9BBC-EE33CC7A0A6F",
        service_url="https://roblox-api.arkoselabs.com",
        window=window,
        fingerprint=fp,
        analytics=True,
        whitelisted_types=[1],
        whitelisted_variants=None,
        proxy=next(proxies) if proxies else None
    )
    return fcs

def prepare_image(im, label=None):
    im = imageutil.remove_background(im)
    im = im.crop(im.getbbox())
    if masking:
        im = imageutil.mask(im)
    return im

class SolverDBSaver(Thread):
    interval = 60

    def __init__(self):
        super().__init__()
    
    def run(self):
        while 1:
            time.sleep(self.interval)
            try:
                ad = pickle.dumps(appear)
                with open("solver-db/appear.p", "wb") as f:
                    f.write(ad)
                cd = pickle.dumps(cache)
                with open("solver-db/cache.p", "wb") as f:
                    f.write(cd)
            except Exception as err:
                print("Save error:", err)

class SolverWorker(Thread):
    def __init__(self):
        super().__init__()
    
    def get_session(self):
        self.session = get_session()
    
    def run(self):
        self.get_session()

        while 1:
            try:
                fc = self.session.get_challenge()
                
                for imdata in fc.images:
                    im = imageutil.to_pil(imdata)
                    mim = prepare_image(im, label="main")
                    mh = imageutil.hash_image(mim, hash_method, hash_length)
                    appear[mh] = 1
                    
                    for rn in range(1, int(360/fc.rotate_degree)):
                        rd = fc.rotate_degree * rn
                        rk = "%s|%.2f" % (mh, rd)
                        rh = cache.get(rk)
                        if not rh:
                            rim = prepare_image(im.rotate(rd*-1), label="rotate")
                            rh = imageutil.hash_image(rim, hash_method, hash_length)
                            cache[rk] = rh
                        if not rh in appear:
                            break

                    solved = fc.check_answer(rd)
                
                if solved:
                    solved_queue.put(fc)
                    solver_success_counter.add()
                else:
                    solver_failure_counter.add()

            except (BannedProxy, BadGameTypeOrVariant, Exception) as err:
                self.session.close_conns()
                self.get_session()

## Account creation functions, workers and exceptions
class SignupError(Exception): pass
class CaptchaError(Exception): pass
class CreatedAccount:
    def __init__(self, id, username, password, cookie):
        self.id = id
        self.username = username
        self.password = password
        self.cookie = cookie

    def safe_cookie(self):
        return self.cookie.replace("WARNING:", "WARNING")
    
    def __repr__(self):
        return self.username

error_assoc = {2: CaptchaError}
def raise_for_error(r):
    d = r.json()
    if not "errors" in d: return
    for err in d["errors"]:
        e = error_assoc.get(err["code"], SignupError)
        raise e("%s (code %d)" % (err["message"], err["code"]))

def create_account(ch):
    username = gen_username()
    password = gen_password()
    def send():
        return requests.post(
            url="https://auth.roblox.com/v2/signup",
            headers={**bheaders, "X-CSRF-TOKEN": ch.proxy.xsrf_token or "-"},
            proxies={"https": "%s:%d" % (ch.proxy.host, ch.proxy.port)},
            timeout=10,
            json=dict(
                username=username,
                password=password,
                gender="Male",
                birthday="2000-01-01",
                isTosAgreementBoxChecked=True,
                captchaToken=ch.full_token,
                captchaProvider="PROVIDER_ARKOSE_LABS"
            )
        )
    r = send()
    if "x-csrf-token" in r.headers:
        ch.proxy.xsrf_token = r.headers["x-csrf-token"]
        r = send()
    raise_for_error(r)
    data = r.json()
    cookie = r.cookies[".ROBLOSECURITY"]
    account = CreatedAccount(data["userId"], username, password, cookie)
    return account


class ResubmitWorker(Thread):
    def __init__(self):
        super().__init__()
    
    def run(self):
        while 1:
            ch = resubmit_queue.get(True)
            if ch.resubmitted: continue

            try:
                ch.resubmitted = True
                if ch.check_answer(None, bypass=True):
                    solved_queue.put(ch)

            except Exception as err:
                print("Error while attempting to resubmit challenge:", err)


class TitleWorker(Thread):
    interval = 0.1

    def __init__(self):
        super().__init__()
    
    def run(self):
        while 1:
            time.sleep(self.interval)
            st = solver_success_counter.total+solver_failure_counter.total
            ratio = (solver_success_counter.total/st) * 100 if st else 0
            s = "  |  ".join([
                "Created: %d" % created_counter.total,
                "CPM: %d" % created_counter.cpm(),
                "Solve Ratio: %.2f%% (S:%d,F:%d)" % (ratio, solver_success_counter.total, solver_failure_counter.total)
            ])
            ctypes.windll.kernel32.SetConsoleTitleW(s)

class Worker(Thread):
    def __init__(self):
        super().__init__()

    def run(self):
        while 1:
            ch = solved_queue.get(True)

            try:
                account = create_account(ch)
                resubmit_queue.put(ch)
                account_callback(account)
            
            except CaptchaError:
                print("Token was rejected by Roblox")
            
            except SignupError as err:
                print("Roblox returned error while creating account:", err)
                resubmit_queue.put(ch)

            except Exception as err:
                print("Unexpected error:", err)

## Start threads
TitleWorker().start()
SolverDBSaver().start()
for _ in range(thread_count):
    Worker().start()
for _ in range(resubmitter_count):
    ResubmitWorker().start()
for _ in range(solver_count):
    SolverWorker().start()