from asyncio import create_task, Task, CancelledError
from traceback import format_exc

from aioconsole import ainput
from mitmproxy.ctx import log, master
from mitmproxy.http import HTTPFlow
from mitmproxy.websocket import WebSocketMessage
from win32clipboard import OpenClipboard, GetClipboardData, CloseClipboard

from TestScript52 import *
from TestScript55 import *

true, false, null = True, False, None
l = log.info

sid: str = '0' * 0x20

key: bytes = b'\x00' * 0x20
iv: bytes = b'\x00' * 0x10

ws_sender_task = None

suppress_fails: bool = False

modify_init_progress: bool = False
init_progress_data: dict[str:str] = {
    "version_slot": version
}
if modify_init_progress:
    with open(r"playerData.json", 'rb') as f:
        init_progress_data |= loads(f.read())

modify_device: bool = False
modify_auth: bool = False
ids: list = ["205678791", "265220424", "283382747", "234993327", "194682621", "272747645", "202953141", "89648720", "235374703", "253064086", "151907445", "276851715", "214013200", "232826149", "214142200", "226109135", "168869777", "152163170", "222960932", "283355160", "218012511", "247124654", "237461288", "268835671", "134465863", "215572367", "144954109", "271177111", "245134618", "270721444", "241587255", "133041541", "280391652", "216827531", "171489656", "205149248", "268832560", "257550421", "278488660", "254991451", "195400649", "267723679", "278958662", "165029460", "274362257", "272604613", "272977881", "135774313", "265546626","280165788", "272678334", "217130605", "284175052", "174889253", "277334739", "213582464", "101701975", "242306168", "114709870", "225402379", "249733553", "226954642", "189100038", "192138828", "225076894", "127571609", "213650274", "284878434", "254746082", "233820562", "245704893", "123949352", "256832821", "137986731", "277931186", "227136574", "203346496", "267514832", "231836795", "240477870", "237289977", "149246865", "173094273", "271508538", "224018012", "269981645", "256205137", "266529464", "232657579", "269906722", "134020449", "192976574", "252817873", "222521568", "268087486", "247341422", "267752783", "249901857", "269359963","245462416", "254067503", "204995544", "154153624", "210314575", "107737097", "287234389", "124861569", "239049288", "218471008", "278642763", "221419855", "202143831", "265892776", "150197917", "195412111", "222373649", "225674098", "176787796", "210117304", "209371543", "200065022", "177915061", "205335644", "258548281", "273099178", "250108742", "189084315", "273644645", "214345499", "181547151", "247576577", "250460981", "207855217", "116469388", "106087532", "253428544", "200542782", "175228103", "178621621", "151160572", "95523376", "149730430", "143475275", "228187902", "116131680", "236711008", "229865529", "90603419", "256230276", "287904298"]

uuid: str = ''  # "2564fb60-b834-4b18-8278-3bce7ab764d5"
device: str = "RT4E-aac6fe77a4673cd5565be300c46bcd98"
uniq_id: str = ''  # f"{269356582}"
id_seed: str = f"{randint(100000000, 999999999)}"

token: str = "897a5b6c4da0b263ca5fce3ad13e669b1d878544e2ebaef1549f22712e96ac6d121bf6525cf21dd6adb195d3fb00fa1b6e24bd52922e0b192c5336bbac1711f5f6ff369be58d58d0df758286a33f42b24fe410b003697da85f4f1e7a2d7403faa26ece12a0d27d28f4fd7ca4678b1415eedcef9781800ca772efda484445a197 "
new_account: bool = False

blacklist: set[str] = {
    "applovin",
    "doubleclick",
    "googleads",
    "unity3d",
    "inner-active",
    "app-measurement",
    "appmeasurements",
    "gstatic",
    "adjust",
    "adinmo",
    "trnox",
    "tapjoy",
    "appsflyer",
    "clicktale",
    "facebook",
    "amazon-adsystem",
    "mopub",
    "cloudfront",
    "smaato",
    "aarki",
    "trustarc",
    "adsafeprotected",
    "serving-sys",
    "googlesyndication",
    "applvn",
    "vungle",
    "supersonicads",
    "xiaomi",
    "yeshen"
}
whitelist: set[str] = {
    "pixelgunserver",
    "pixelgun3dserver"
}


def is_encrypted(byte: bytes) -> bool:
    for I in byte:
        if 32 > I or I > 126:
            return True
    return False


def send_websocket(flow: HTTPFlow, pkt: list):
    global key, iv
    for msg in packet_encrypt(key, iv, pkt, from_client=True):
        master.commands.call("inject.websocket", flow, False, msg, False)


def websocket_message(flow: HTTPFlow):
    global key, iv, sid, ws_sender_task, init_progress_data
    m: WebSocketMessage = flow.websocket.messages[-1]
    ws: bytes = m.content
    if ws.startswith(b'0{"sid":"'):
        j: dict = loads(ws[1:])

        sid = j["sid"]  # j["sid"] = sid

        ws = m.content = ws[:1] + dumps(j, separators=(',', ':')).encode()
    elif len(ws) > 1 and len(ws) % 16 == 1 and ws[0] == 4:
        if is_encrypted(ws := websocket_decrypt(key, iv, ws[1:])):
            key, iv = websocket_key_iv(sid=sid)
            l(f"AES256 Key & IV Used: {key.hex().upper()}-{iv.hex().upper()}")
            ws: bytes = websocket_decrypt(key, iv, m.content[1:])
        try:
            ws: Any = loads(ws)
            if isinstance(ws, dict):
                if modify_init_progress:
                    if "progress" in ws and "version_slot" in ws["progress"] and isinstance(ws["progress"], dict) and \
                            "hash" in ws and "hash_version" in ws and "prop" in ws:
                        init_progress_data = ws["progress"] = ws["progress"] | init_progress_data
                    elif (('i' in ws and ws['i'] in ('', None)) or "progress" in ws) and "status" in ws and "req_id" \
                            in ws and len(ws) > 2:
                        if ws["status"] == 'ok' and 3 <= len(ws) <= 4:
                            ws["progress"] = init_progress_data | {"subscriptions": {}}
                        ws['i'] = None
                if 'p' in ws and isinstance(ws['p'], dict) and 'c' in ws['p'] and isinstance(ws['p']['c'], list):
                    for info in ws['p']['c']:
                        if isinstance(info, dict) and 'id' in info and 'h' in info:
                            info['h'] = {}
                elif (modify_device or modify_auth) and "device" in ws:
                    ws["device"] = device
                    if modify_auth:
                        ws["hash"] = uuid
                        ws["uniq_id"] = uniq_id
                elif "app_version" in ws and ':' in ws["app_version"]:
                    ws["app_version"] = ws["app_version"].split(':')[0] + ':' + version
                elif "progress" in ws and "version_slot" in ws["progress"] and isinstance(ws["progress"], dict):
                    ws["progress"]["version_slot"] = version
                elif "slots" in ws and "version_slot" in ws["slots"] and isinstance(ws["slots"], dict):
                    ws["slots"]["version_slot"] = version
                elif "developer" in ws and ws["developer"] == 0:
                    ws["developer"] = 1
                elif "develop" in ws and ws["develop"] == 0:
                    ws["develop"] = 1
                if suppress_fails:
                    if "status" in ws and ws["status"] == "fail":
                        ws["status"] = "ok"
                    if "err_code" in ws and isinstance(ws["err_code"], int):
                        del ws["err_code"]
                    if "new_err" in ws and ws["new_err"] == 1:
                        ws["new_err"] = 0
            elif isinstance(ws, str) and ws.startswith("auth") and (
                    ws_sender_task is None or (isinstance(ws_sender_task, Task) and ws_sender_task.cancelled())):
                ws_sender_task = create_task(websocket_sender(flow))
            ws: bytes = dumps(ws).encode()
        except (JSONDecodeError, UnicodeDecodeError):
            pass
        finally:
            m.content = m.content[:1] + websocket_encrypt(key, iv, ws)
    try:
        l(f"{'>' if m.from_client else '<'}: {ws.decode() if isinstance(ws, bytes) else ws}")
    except UnicodeDecodeError:
        l(f"{'>' if m.from_client else '<'}: {ws.hex()}")


def clipboard():
    OpenClipboard()
    try:
        return eval(GetClipboardData().strip().replace('\n', ''))
    finally:
        CloseClipboard()


async def websocket_sender(flow: HTTPFlow):
    l("Starting Websocket Sender...")
    while flow.websocket.timestamp_end is None and flow.websocket.closed_by_client is None:
        try:
            cmd: str = (await ainput()).strip().replace('\n', '')
            if cmd.endswith("clear"):
                l("Cleared Websocket Command Cache.")
                continue
            if cmd.startswith('/'):
                exec(cmd.lstrip('/').strip())
            else:
                send_websocket(flow, eval(cmd))
        except CancelledError:
            break
        except:
            l(f"Unexpected Error:\n{'=' * 32}\n{format_exc().strip()}\n{'=' * 32}\nWhile Executing Websocket Command!")
    l("Closing Websocket Sender...")


def websocket_change(flow: HTTPFlow):
    global ws_sender_task
    if isinstance(ws_sender_task, Task) and not ws_sender_task.cancelled():
        l(f"Cancelling Websocket Sender for Flow Started @ {flow.timestamp_start} ...")
        ws_sender_task.cancel()
        ws_sender_task = None


websocket_start = websocket_end = websocket_change


def request(flow: HTTPFlow):
    l(f">: {flow.request.pretty_url}")
    l(f"{flow.request.headers}")
    for whitelisted in whitelist:
        if whitelisted in flow.request.pretty_host:
            m = flow.request.content
            if "/auth" in flow.request.pretty_url:
                m = https_decrypt(m)
                if modify_device:
                    flow.request.content = device_changer(flow.request.content, device)
                    m = https_decrypt(flow.request.content)
                if modify_auth:
                    m["hash"] = uuid
                    m["device_id"] = device
                    m["uniq_id"] = uniq_id
                    m["id_seed"] = id_seed
                    m["version"] = version
                if new_account:
                    m["new_id_v3"] = str(int(new_account))
                if modify_auth or new_account:
                    flow.request.content = https_encrypt(m)
                m = dumps(m)
            try:
                l(f">: {m.decode() if isinstance(m, bytes) else m}")
            except UnicodeDecodeError:
                l(f">: {m.hex()}")
            return
    for blacklisted in blacklist:
        if blacklisted in flow.request.pretty_host and flow.killable:
            flow.kill()
            return


def response(flow: HTTPFlow):
    l(f"<: {flow.request.pretty_url}")
    l(f"{flow.response.headers}")
    for whitelisted in whitelist:
        if whitelisted in flow.request.pretty_host:
            m = flow.response.content
            if "/auth" in flow.request.pretty_url:
                try:
                    m = https_decrypt(m)
                    if "status" in m and m["status"] == "fail":
                        raise IndexError("Status is Failed!")
                except IndexError as ie:
                    if suppress_fails:
                        flow.response.status_code = 200
                        flow.response.content = https_encrypt(m := {
                            "url": "https://server-v2.pixelgun3dserver.com/socket.io/",
                            "req_id": "0",
                            "token": token,
                            "namespace": "/sio",
                            "wait": "600",
                            "status": "ok",
                            "time": f"{round(time())}",
                            "service_id": "1",
                            "mm_url": ""
                        })
                    else:
                        l(f'Error: "{str(ie).title()}" while Decrypting HTTPS Response!')
                m = dumps(m)
            try:
                l(f"<: {m.decode() if isinstance(m, bytes) else m}")
            except UnicodeDecodeError:
                l(f"<: {m.hex()}")
            return
