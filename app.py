#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jdback — 京东 code / wskey 登录 Flask Web 服务。

端点:
  POST /api/jd-check    — 小程序 code 登录（原有）
  POST /api/jd-wskey    — wskey 转 cookie（新增）

wskey 是京东长期保活令牌，可通过 yyb_go 的 /wxapp/getJdWskey 接口获取。
拿到 wskey 后调用本接口即可转换为 pt_key/pt_pin cookie。
"""

from __future__ import annotations

import base64
import functools
import hashlib
import random
import uuid
import hmac
import ipaddress
import json
import html
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Any, Dict, Iterable, Optional, Tuple

from curl_cffi.requests import Session as CurlSession
from flask import Flask, request, jsonify

# ========== 环境变量配置 ==========

def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name) or default).strip()

AUTORPOST_TOKEN = _env("AUTORPOST_TOKEN")
JD_APPID = _env("JD_APPID", "wx91d27dbf599dff74")
JD_PT_APPID = _env("JD_PT_APPID", "wx2f5d8f9715c59d10")
JD_PT_APP = "300"
JD_PT_RETURN_URL = "https://my.m.jd.com/account/index.html"
YYB_API_TOKEN = _env("YYB_API_TOKEN")

try:
    REQUEST_TIMEOUT = max(5, min(int(_env("REQUEST_TIMEOUT", "30")), 90))
except ValueError:
    REQUEST_TIMEOUT = 30

JD_DEBUG = _env("JD_DEBUG", "0").lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_YYB = _env("ALLOW_INSECURE_YYB", "0").lower() in {"1", "true", "yes", "on"}

# 京东 wskey 转 cookie 的 UA（模拟京东 Android APP，与 appid=jd_android 渠道保持一致）
JD_WSKEY_UA = (
    "JD4Android/13.6.4;Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36"
)

# ── 京东 APP genToken 签名（移植自 Zy143L/wskey；sign 必需，缺失会得到 {"code":"1","echo":"no access"}）──
_JD_SIGN_ARR = [0x37, 0x92, 0x44, 0x68, 0xA5, 0x3D, 0xCC, 0x7F, 0xBB, 0x0F, 0xD9, 0x88, 0xEE, 0x9A, 0xE9, 0x5A]
_JD_SIGN_KEY = b"80306f4370b39fd5630ad0529f77adb6"
JD_GENTOKEN_BODY = '{"to":"https%3a%2f%2fplogin.m.jd.com%2fjd-mlogin%2fstatic%2fhtml%2fappjmp_blank.html"}'
JD_APPJMP_TO = "https://plogin.m.jd.com/jd-mlogin/static/html/appjmp_blank.html"


def _jd_sign_core(par: bytes) -> bytes:
    arr = _JD_SIGN_ARR
    key2 = _JD_SIGN_KEY
    out = [0] * len(par)
    for i in range(len(par)):
        r0 = int(par[i])
        r2 = arr[i & 0xF]
        r4 = int(key2[i & 7])
        r0 = r2 ^ r0
        r0 = r0 ^ r4
        r0 = r0 + r2
        r2 = r2 ^ r0
        r2 = r2 ^ int(key2[i & 7])
        out[i] = r2 & 0xFF
    return bytes(out)


def _jd_gen_sign(function_id: str, body: str, uu: str, client: str, cv: str, st: int, sv: str) -> str:
    raw = "functionId=%s&body=%s&uuid=%s&client=%s&clientVersion=%s&st=%s&sv=%s" % (
        function_id, body, uu, client, cv, st, sv)
    return hashlib.md5(base64.b64encode(_jd_sign_core(raw.encode()))).hexdigest()


def _jd_b64e(s: str) -> str:
    a = "KLMNOPQRSTABCDEFGHIJUVWXYZabcdopqrstuvwxefghijklmnyz0123456789+/"
    b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return base64.b64encode(s.encode()).decode().translate(str.maketrans(a, b))


def _jd_app_ua(st: int, aid: str, oaid: str) -> str:
    return ('jdapp;android;11.1.4;;;appBuild/98176;ef/1;ep/{"hdid":"JM9F1ywUPwflvMIpYPok0tt5k9kW4ArJEU3lfLhxBqw=",'
            '"ts":%s,"ridx":-1,"cipher":{"sv":"CJS=","ad":"%s","od":"%s","ov":"CzO=","ud":"%s"},'
            '"ciphertype":5,"version":"1.2.0","appname":"com.jingdong.app.mall"};'
            'Mozilla/5.0 (Linux; Android 12; M2102K1C Build/SKQ1.220303.001; wv) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Version/4.0 Chrome/97.0.4692.98 Mobile Safari/537.36'
            % (st, aid, oaid, aid))


def _wskey_cookie_header(cred: str) -> str:
    """把录入的凭证串规范成 genToken 需要的 Cookie。
    实测（2026-10 验证）：genToken 必须同时带 ``wskey=`` 和 ``pin=``（用 ``pt_pin=`` 会失败）。
    支持输入 "pin=xxx;wskey=AAJ..." 或裸 "AAJ..."。"""
    raw = str(cred or "").strip().rstrip(";")
    if "wskey=" not in raw:
        raw = "wskey=" + raw
    return raw + ";"


def _jd_cookie_alive(cookie: str) -> bool:
    """用 cookie 调京东用户信息接口判断是否真的有效（返回 not login 即失败）。"""
    ck = normalize_pt_cookie(cookie)
    if not ck:
        return False
    if "fake" in ck.lower():
        return False
    try:
        session = CurlSession(impersonate="chrome120")
        try:
            resp = session.get(
                "https://me-api.jd.com/user_new/info/GetJDUserInfoUnion?agentId=1&appName=jd-cphdeveloper-m&key=",
                headers={"Cookie": ck, "User-Agent": UA_DEFAULT, "Referer": "https://home.m.jd.com/"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )
            body = resp.text or ""
        finally:
            session.close()
    except Exception as exc:
        _diag(f"  活性校验异常: {exc}")
        return False
    if "not login" in body or "\"retcode\":\"1001\"" in body:
        return False
    return ('"assetInfo"' in body) or ('"userInfo"' in body) or ('"nickName"' in body) or ('"nickname"' in body)


def _jd_classic_params(suid: str, ep: str, st: int, sv: str, sign: str) -> dict:
    return {
        "functionId": "genToken", "clientVersion": "11.1.4", "build": "98176", "client": "android",
        "partner": "google", "oaid": suid, "sdkVersion": "31", "lang": "zh_CN", "harmonyOs": "0",
        "networkType": "UNKNOWN", "uemps": "0-2", "ext": '{"prstate": "0", "pvcStu": "1"}',
        "eid": "eidAcef08121fds9MoeSDdMRQ1aUTyb1TyPr2zKHk5Asiauw+K/WvS1Ben1cH6N0UnBd7lNM50XEa2kfCcA2wwThkxZc1MuCNtfU/oAMGBqadgres4BU",
        "ef": "1", "ep": ep, "st": st, "sv": sv, "sign": sign,
    }


# ========== 常量 ==========


UA_WX = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 "
    f"MicroMessenger/8.0.53 NetType/WIFI Language/zh_CN miniProgram/{JD_APPID}"
)
UA_DEFAULT = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 "
    "Mobile Safari/537.36"
)

# ========== HTTP 工具 ==========

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CookieOpener:
    def __init__(self):
        self.cookie_jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
            NoRedirectHandler(),
        )

    def open(self, request, timeout=30):
        return self.opener.open(request, timeout=timeout)


def redact_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(parsed._replace(query="", fragment=""))


def _is_local_host(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_yyb_server(raw: str) -> str:
    value = str(raw or "").strip().splitlines()[0].rstrip("/")
    if "@" in value:
        value = value[: value.index("@")].rstrip("/")
    if not value:
        raise ValueError("缺少 yyb_server 参数")
    if "://" not in value:
        value = "https://" + value

    parsed = urllib.parse.urlparse(value)
    host = parsed.hostname or ""
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError("yyb_server 必须是有效的 HTTP/HTTPS 地址")
    if parsed.username or parsed.password:
        raise ValueError("yyb_server 不允许包含用户名或密码")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError("yyb_server 不允许包含参数、查询字符串或片段")
    if parsed.scheme != "https" and not (_is_local_host(host) or ALLOW_INSECURE_YYB):
        raise ValueError(
            "yyb_server 必须使用 HTTPS；如确需连接可信内网 HTTP 服务，"
            "请设置 ALLOW_INSECURE_YYB=1"
        )
    return urllib.parse.urlunparse(
        parsed._replace(path=parsed.path.rstrip("/"), params="", query="", fragment="")
    )


_DIAG_T0 = time.monotonic()


def _diag(msg: str) -> None:
    if JD_DEBUG:
        print(f"  [诊断 +{time.monotonic() - _DIAG_T0:6.1f}s] {msg}")


def risk_fingerprint(url: str) -> str:
    if not url:
        return "(无)"
    try:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        token = (query.get("token") or [""])[0]
        guid = (query.get("guid") or [""])[0]

        def short(value: str) -> str:
            if len(value) <= 12:
                return value or "(空)"
            return f"{value[:6]}…{value[-4:]}"

        return f"token={short(token)} guid={short(guid)}"
    except Exception:
        return "(解析失败)"


def request_text(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    opener: Optional[CookieOpener] = None,
    json_body: bool = True,
) -> Tuple[int, Dict[str, str], str]:
    request_headers = dict(headers or {})
    if "User-Agent" not in request_headers:
        request_headers["User-Agent"] = UA_DEFAULT
    body = None
    if data is not None:
        if json_body:
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        else:
            body = data.encode("utf-8") if isinstance(data, str) else data
    request = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method=method.upper(),
    )
    try:
        response = (
            opener.open(request, timeout=REQUEST_TIMEOUT)
            if opener is not None
            else urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT)
        )
        with response as resp:
            response_headers: Dict[str, str] = {}
            for header_name, header_value in resp.headers.items():
                if header_name.lower() == "set-cookie" and header_name in response_headers:
                    response_headers[header_name] += "; " + str(header_value)
                else:
                    response_headers[header_name] = str(header_value)
            return (
                int(getattr(resp, "status", 200)),
                response_headers,
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        response_headers: Dict[str, str] = {}
        for header_name, header_value in exc.headers.items():
            if header_name.lower() == "set-cookie" and header_name in response_headers:
                response_headers[header_name] += "; " + str(header_value)
            else:
                response_headers[header_name] = str(header_value)
        return (
            int(exc.code),
            response_headers,
            exc.read().decode("utf-8", "replace"),
        )
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(
            f"请求失败 {method.upper()} {redact_url(url)}：{reason}"
        ) from exc


def parse_jsonish(raw: str) -> Dict[str, Any]:
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {"value": value}
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            try:
                value = json.loads(text[start : end + 1])
                return value if isinstance(value, dict) else {"value": value}
            except json.JSONDecodeError:
                pass
    return {}


def response_message(payload: Any) -> str:
    value = nested_value(
        payload,
        (
            "errmsg", "errMsg", "message", "msg", "error",
            "retmsg", "retMessage", "returnMsg", "return_msg",
            "err_msg", "desc", "description",
            "info", "reason", "detail", "data",
        ),
    )
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)[:500]
        if isinstance(value, dict):
            inner = nested_value(value, ("msg", "message", "errmsg", "errMsg", "error", "desc"))
            if inner and isinstance(inner, str):
                return inner.strip()[:300]
        return text
    return str(value or "").strip()[:300]


def request_json(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    opener: Optional[CookieOpener] = None,
    yyb_server: str = "",
) -> Dict[str, Any]:
    merged_headers = dict(headers or {})
    if YYB_API_TOKEN and yyb_server and url.startswith(yyb_server):
        merged_headers.setdefault("Authorization", f"Bearer {YYB_API_TOKEN}")
    status, _headers, raw = request_text(method, url, merged_headers, data, opener)
    payload = parse_jsonish(raw)
    if status < 200 or status >= 300:
        message = response_message(payload)
        if status == 409 and "login_buffer expired" in message.lower():
            message = "应用宝账号登录缓存已过期，请打开 /scan 重新扫码"
        suffix = f"：{message}" if message else ""
        raise RuntimeError(
            f"HTTP {status} {method.upper()} {redact_url(url)}{suffix}"
        )
    if not payload and raw.strip():
        raise RuntimeError(
            f"接口未返回 JSON：{method.upper()} {redact_url(url)}"
        )
    return payload


def unwrap_service_payload(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {"value": payload}
    if "code" in payload and "data" in payload:
        code = str(payload.get("code"))
        if code not in {"0", "200", "201"}:
            raise RuntimeError(response_message(payload) or f"接口业务状态异常：{code}")
        data = payload.get("data")
        if isinstance(data, dict):
            return data
        if isinstance(data, str) and data.strip().startswith(("{", "[")):
            decoded = parse_jsonish(data)
            if decoded:
                return decoded
        return {"value": data}
    return payload


def nested_value(payload: Any, keys: Iterable[str]) -> Any:
    wanted = set(keys)
    wanted_lower = {str(key).lower() for key in wanted}
    if isinstance(payload, dict):
        for key, value in payload.items():
            if (
                (key in wanted or str(key).lower() in wanted_lower)
                and value not in (None, "")
            ):
                return value
        for value in payload.values():
            found = nested_value(value, wanted)
            if found not in (None, ""):
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = nested_value(value, wanted)
            if found not in (None, ""):
                return found
    elif isinstance(payload, str):
        text = payload.strip()
        if text.startswith(("{", "[")):
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                decoded = None
            if isinstance(decoded, (dict, list)):
                return nested_value(decoded, wanted)
    return None


def nested_string(payload: Any, keys: Iterable[str]) -> str:
    value = nested_value(payload, keys)
    if isinstance(value, str):
        return value.strip()
    return ""


# ========== Cookie 工具 ==========

def normalize_pt_cookie(cookie: Any) -> str:
    if isinstance(cookie, CookieJar):
        values: Dict[str, str] = {}
        for item in cookie:
            if item.name in {"pt_key", "pt_pin"} and item.value:
                values[item.name] = str(item.value)
        if values.get("pt_key") and values.get("pt_pin"):
            return f"pt_key={values['pt_key']};pt_pin={values['pt_pin']};"
        return ""

    text = str(cookie or "")
    key_match = re.search(r"(?:^|[;?,\s])pt_key=([^;?,\s]+)", text)
    pin_match = re.search(r"(?:^|[;?,\s])pt_pin=([^;?,\s]+)", text)
    if not key_match or not pin_match:
        return ""
    return f"pt_key={key_match.group(1)};pt_pin={pin_match.group(1)};"


def cookie_from_headers(headers: Dict[str, Any]) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() not in {"set-cookie", "set-cookie2"}:
            continue
        cookie = normalize_pt_cookie(str(value))
        if cookie:
            return cookie
    return ""


def cookie_from_payload(payload: Any) -> str:
    pt_key = nested_string(payload, ("pt_key", "ptKey"))
    pt_pin = nested_string(payload, ("pt_pin", "ptPin"))
    if pt_key and pt_pin:
        return normalize_pt_cookie(f"pt_key={pt_key};pt_pin={pt_pin};")
    return normalize_pt_cookie(str(payload or ""))


def jar_get(jar: CookieJar, name: str) -> str:
    for item in jar:
        if item.name == name and item.value:
            return str(item.value)
    return ""


def all_cookie_text(jar: CookieJar) -> str:
    values: Dict[str, str] = {}
    for cookie in jar:
        if cookie.name and cookie.value is not None:
            values[cookie.name] = str(cookie.value)
    return ";".join(f"{key}={value}" for key, value in values.items()) + (
        ";" if values else ""
    )


def cookie_pin(cookie: str) -> str:
    pure = normalize_pt_cookie(cookie)
    match = re.search(r"(?:^|[;,\s])pt_pin=([^;,\s]+)", pure)
    return match.group(1) if match else ""


def pt_key_type(cookie: str) -> str:
    """判断 pt_key 的签发渠道：
    - "app"   : app_open 开头，京东 APP 渠道登录态（wskey 转换的典型产物）
    - "wskey" : AAJ 开头（wskey 被直接当作 pt_key 使用）
    - "wxapp" : 其他（小程序/H5 登录产物，yyb code 登录流程得到的就是这种）
    """
    match = re.search(r"(?:^|[;,\s])pt_key=([^;,\s]+)", str(cookie or ""))
    if not match:
        return ""
    value = match.group(1)
    if value.startswith("app_open"):
        return "app"
    if value.startswith("AAJf"):
        return "wskey"
    return "wxapp"


def normalize_pin(pin: str) -> str:
    raw = str(pin or "").strip()
    if not raw:
        return ""
    try:
        return urllib.parse.quote(urllib.parse.unquote(raw), safe="")
    except Exception:
        return raw


def login_info(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    info = payload.get("info")
    if isinstance(info, dict):
        return info
    data = payload.get("data")
    if isinstance(data, dict):
        nested = data.get("info")
        return nested if isinstance(nested, dict) else data
    return payload


# ========== 京东 code 登录逻辑（原有）==========

def get_yyb_code(
    yyb_server: str,
    ref: str,
    app_id: Optional[str] = None,
) -> str:
    request_app_id = str(app_id or JD_APPID).strip()
    payload = request_json(
        "POST",
        f"{yyb_server}/wxapp/getCode",
        data={"ref": ref, "app_id": request_app_id},
        yyb_server=yyb_server,
    )
    result = unwrap_service_payload(payload)
    code = nested_string(result, ("wxCode", "wx_code", "jsCode", "jscode", "code"))
    if len(code) < 8 or code in {"0", "200", "201"}:
        raise RuntimeError("应用宝 getCode 未返回有效一次性 code")
    return code


def get_yyb_user_info(yyb_server: str, ref: str) -> Dict[str, str]:
    payload = request_json(
        "POST",
        f"{yyb_server}/wxapp/operateWxData",
        data={
            "ref": ref,
            "app_id": JD_APPID,
            "payload": {
                "api_name": "getUserInfo",
                "data": {"withCredentials": True},
                "env": 1,
            },
        },
        yyb_server=yyb_server,
    )
    result = unwrap_service_payload(payload)
    raw_data = nested_value(result, ("rawData", "raw_data"))
    if raw_data in (None, ""):
        user_info = nested_value(result, ("userInfo", "user_info"))
        if isinstance(user_info, str) and user_info.strip().startswith("{"):
            try:
                user_info = json.loads(user_info)
            except json.JSONDecodeError:
                user_info = None
        if not isinstance(user_info, dict):
            standard_keys = (
                "nickName", "gender", "language", "city",
                "province", "country", "avatarUrl",
            )
            direct_info: Dict[str, Any] = {}
            for key in standard_keys:
                value = nested_value(result, (key,))
                if value is not None:
                    direct_info[key] = value
            user_info = direct_info or None
        if isinstance(user_info, dict) and user_info:
            raw_data = json.dumps(
                user_info, ensure_ascii=False, separators=(",", ":"),
            )
    if isinstance(raw_data, (dict, list)):
        raw_data_text = json.dumps(raw_data, ensure_ascii=False, separators=(",", ":"))
    else:
        raw_data_text = str(raw_data or "").strip()
    encrypted = nested_string(
        result,
        ("encryptedData", "encrytData", "encrypted_data", "encrypteddata"),
    )
    info = {
        "rawData": raw_data_text,
        "signature": nested_string(result, ("signature",)),
        "encrytData": encrypted,
        "iv": nested_string(result, ("iv",)),
        "openid": nested_string(result, ("openid", "openId", "open_id")),
    }
    missing = [key for key in ("rawData", "signature", "encrytData", "iv") if not info[key]]
    if missing:
        result_keys = []
        if isinstance(result, dict):
            result_keys = [str(key) for key in result.keys()][:20]
        detail = "；返回字段=" + ",".join(result_keys) if result_keys else ""
        raise RuntimeError("应用宝 getUserInfo 缺少字段：" + ",".join(missing) + detail)
    return info


def login_headers() -> Dict[str, str]:
    return {
        "User-Agent": UA_WX,
        "Referer": f"https://servicewechat.com/{JD_APPID}/873/page-frame.html",
        "Accept": "application/json,text/plain,*/*",
    }


def call_login_lt(
    opener: CookieOpener,
    code: str,
    user_info: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    params = {
        "appid": JD_APPID,
        "code": code,
        "type": "silent",
        "isPopup": "false",
        "isIgnoreCookie": "false",
        "isOfficialPin": "false",
        "loginColor": "{}",
        "returnUrl": "pages/my/index/index",
        "deviceName": "iPhone",
        "deviceOS": "iOS",
        "deviceOSVersion": "17.0",
        "deviceVersion": "8.0.49",
        "g_tk": "0",
        "g_ty": "ls",
    }
    if user_info:
        params.update(
            {
                "rawData": user_info["rawData"],
                "signature": user_info["signature"],
                "encrytData": user_info["encrytData"],
                "encryptedData": user_info["encrytData"],
                "iv": user_info["iv"],
                "ou": user_info.get("openid", ""),
            }
        )
    url = "https://wq.jd.com/mlogin/wxapp/login_lt?" + urllib.parse.urlencode(params)
    status, response_headers, raw = request_text(
        "GET", url, headers=login_headers(), opener=opener,
    )
    header_cookie = cookie_from_headers(response_headers)
    if header_cookie:
        opener.last_response_cookie = header_cookie
    if status < 200 or status >= 400:
        raise RuntimeError(f"login_lt HTTP {status}")
    return parse_jsonish(raw)


def allowed_jd_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and (
        host == "jd.com" or host.endswith(".jd.com")
    )


def follow_server_refresh(opener: CookieOpener, payload: Dict[str, Any]) -> str:
    info = login_info(payload)
    current = nested_string(info, ("ACRJUrl", "acrjUrl"))
    state = nested_string(info, ("ACRJState", "acrjState"))
    if not current:
        return ""
    if current.startswith("//"):
        current = "https:" + current
    elif current.startswith("/"):
        current = "https://wq.jd.com" + current
    if state and "ACRJState=" not in current:
        parsed = urllib.parse.urlparse(current)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query.append(("ACRJState", state))
        current = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(query))
        )

    headers = dict(login_headers())
    headers["Accept"] = "text/html,application/xhtml+xml,application/json,*/*;q=0.8"
    for _ in range(8):
        if not allowed_jd_url(current):
            raise RuntimeError("服务端刷新地址不是受信任的京东 HTTPS 域名，已停止")
        status, response_headers, _raw = request_text(
            "GET", current, headers=headers, opener=opener,
        )
        result = normalize_pt_cookie(opener.cookie_jar)
        if not result:
            result = cookie_from_headers(response_headers)
        if result:
            return result
        location = (
            response_headers.get("Location")
            or response_headers.get("location")
            or ""
        )
        if status not in {200, 301, 302, 303, 307, 308} or not location:
            result = normalize_pt_cookie(_raw) or normalize_pt_cookie(opener.cookie_jar)
            if result:
                return result
            break
        current = urllib.parse.urljoin(current, location)
        time.sleep(0.5)
    return normalize_pt_cookie(opener.cookie_jar)


def sfs_exchange_pt_key(opener: CookieOpener, payload: Dict[str, Any]) -> str:
    sfs = jar_get(opener.cookie_jar, "sfstoken")
    pin = jar_get(opener.cookie_jar, "pin") or jar_get(opener.cookie_jar, "pt_pin")
    if not sfs or not pin:
        return ""
    url = "https://wq.jd.com/mlogin/wxapp/sfsRefreshToken?" + urllib.parse.urlencode({
        "appid": JD_APPID,
        "pin": pin,
        "sfstoken": sfs,
        "type": "silent",
        "isPopup": "false",
        "isIgnoreCookie": "false",
        "g_tk": "0",
        "g_ty": "ls",
    })
    status, response_headers, raw = request_text(
        "GET", url, headers=login_headers(), opener=opener,
    )
    cookie = normalize_pt_cookie(opener.cookie_jar)
    if cookie:
        return cookie
    cookie = cookie_from_headers(response_headers)
    if cookie:
        return cookie
    result = parse_jsonish(raw)
    cookie = cookie_from_payload(result)
    if cookie:
        return cookie
    sfs_acrj = nested_string(login_info(result), ("ACRJUrl", "acrjUrl"))
    if sfs_acrj:
        _diag(f"  SFS交换返回了新的风险挑战：{risk_fingerprint(sfs_acrj)}")
    cookie = follow_server_refresh(opener, result)
    if cookie:
        return cookie
    return ""


def jd_pt_headers() -> Dict[str, str]:
    return {
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 "
            "Mobile Safari/537.36 MicroMessenger/8.0.53.2740 "
            "NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "zh-CN,zh;q=0.9",
    }


def jd_pt_allowed_redirect(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and (
        host == "jd.com"
        or host.endswith(".jd.com")
        or host == "jd.hk"
        or host.endswith(".jd.hk")
        or host == "3.cn"
        or host.endswith(".3.cn")
    )


def jd_pt_html_redirect(base_url: str, raw: str) -> str:
    text = html.unescape(str(raw or ""))
    patterns = (
        r"<meta[^>]+url\s*=\s*[\"']?([^\"' >]+)",
        r"(?:window\.)?location(?:\.href)?\s*=\s*[\"']([^\"']+)",
        r"location\.replace\s*\(\s*[\"']([^\"']+)",
        r"location\.assign\s*\(\s*[\"']([^\"']+)",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            candidate = urllib.parse.urljoin(base_url, match.group(1).strip())
            if candidate:
                return candidate
    return ""


def jd_pt_cookie_login(code: str) -> str:
    session = CookieOpener()
    login_url = "https://plogin.m.jd.com/user/login.action?" + urllib.parse.urlencode(
        {"appid": JD_PT_APP, "returnurl": JD_PT_RETURN_URL}
    )
    status, headers, _raw = request_text(
        "GET", login_url, headers=jd_pt_headers(), opener=session
    )
    location = headers.get("Location") or headers.get("location") or ""
    if not location or status < 300 or status >= 400:
        raise RuntimeError(f"JD PT login.action 未跳转：HTTP {status}")
    oauth_url = urllib.parse.urljoin(login_url, location)
    oauth = urllib.parse.urlparse(oauth_url)
    oauth_query = urllib.parse.parse_qs(oauth.query, keep_blank_values=True)
    if oauth_query.get("appid", [""])[0] != JD_PT_APPID:
        raise RuntimeError("JD PT OAuth appid 不匹配")
    redirect_uri = oauth_query.get("redirect_uri", [""])[0]
    state = oauth_query.get("state", [""])[0]
    if not redirect_uri or not state:
        raise RuntimeError("JD PT OAuth 缺少 redirect_uri/state")
    callback = urllib.parse.urlparse(redirect_uri)
    callback_query = urllib.parse.parse_qsl(callback.query, keep_blank_values=True)
    callback_query.extend([("code", code), ("state", state)])
    callback = callback._replace(query=urllib.parse.urlencode(callback_query))
    current = urllib.parse.urlunparse(callback)

    last_status = 0
    for hop in range(8):
        if not jd_pt_allowed_redirect(current):
            raise RuntimeError("JD PT 刷新跳转超出允许的京东域名")
        last_status, response_headers, raw = request_text(
            "GET", current, headers=jd_pt_headers(), opener=session
        )
        if JD_DEBUG:
            hop_path = urllib.parse.urlparse(current).path
            _diag(f"  PT跳转[{hop}] {hop_path} -> HTTP {last_status}")
        cookie = normalize_pt_cookie(session.cookie_jar)
        if not cookie:
            cookie = cookie_from_headers(response_headers)
        if not cookie:
            cookie = normalize_pt_cookie(raw)
        if cookie:
            return cookie
        location = (
            response_headers.get("Location")
            or response_headers.get("location")
            or ""
        )
        if not location and last_status == 200:
            location = jd_pt_html_redirect(current, raw)
        if not location or last_status not in {200, 301, 302, 303, 307, 308}:
            break
        current = urllib.parse.urljoin(current, location)
    cookie_names = ",".join(
        sorted({item.name for item in session.cookie_jar if item.name})
    ) or "无"
    raise RuntimeError(
        "JD PT 刷新链未返回 pt_key/pt_pin；"
        f"last_status={last_status}；Cookie字段={cookie_names}"
    )


def exchange_pt_cookie(yyb_server: str, ref: str) -> str:
    pt_code = get_yyb_code(yyb_server, ref, app_id=JD_PT_APPID)
    return jd_pt_cookie_login(pt_code)


def attempt_code_login(
    yyb_server: str,
    ref: str,
    full: bool = False,
) -> Tuple[str, Optional[str]]:
    label = "full" if full else "code-only"
    t0 = time.monotonic()
    session = CookieOpener()
    code = get_yyb_code(yyb_server, ref)
    user_info = get_yyb_user_info(yyb_server, ref) if full else None
    _diag(f"[{label}] 已取得 " + ("code+userInfo" if full else "code") + f"，用时{time.monotonic()-t0:.1f}s")
    payload = call_login_lt(session, code, user_info)
    first_acrj = nested_string(login_info(payload), ("ACRJUrl", "acrjUrl"))
    if first_acrj:
        _diag(f"[{label}] login_lt 直接返回风险挑战：{risk_fingerprint(first_acrj)}")
    else:
        _diag(f"[{label}] login_lt 未触发风险挑战（retMsg={response_message(payload) or '(空)'}）")
    cookie = normalize_pt_cookie(session.cookie_jar)
    if not cookie:
        cookie = str(getattr(session, "last_response_cookie", "") or "")
    if not cookie:
        cookie = cookie_from_payload(payload)
    if not cookie:
        cookie = follow_server_refresh(session, payload)
    if cookie:
        _diag(f"[{label}] ✅ login_lt/follow_refresh 直接拿到 pt_key，总用时{time.monotonic()-t0:.1f}s")
        return normalize_pt_cookie(cookie), None
    sfs_cookie = sfs_exchange_pt_key(session, payload)
    if sfs_cookie:
        _diag(f"[{label}] ✅ SFS交换拿到 pt_key，总用时{time.monotonic()-t0:.1f}s")
        return normalize_pt_cookie(sfs_cookie), None
    exchange_error = ""
    try:
        pt_cookie = exchange_pt_cookie(yyb_server, ref)
        _diag(f"[{label}] ✅ PT OAuth 链拿到 pt_key，总用时{time.monotonic()-t0:.1f}s")
        return pt_cookie, None
    except Exception as exc:
        exchange_error = str(exc)
        _diag(f"[{label}] ❌ PT OAuth 链也失败：{exchange_error}")
    _diag(f"[{label}] ❌ 全部手段均未拿到 pt_key，总用时{time.monotonic()-t0:.1f}s")
    risk_url = first_acrj or nested_string(login_info(payload), ("ACRJUrl", "acrjUrl"))
    message = response_message(payload)
    raw_payload_snippet = ""
    try:
        raw_payload_snippet = json.dumps(payload, ensure_ascii=False)[:500]
    except Exception:
        raw_payload_snippet = str(payload)[:500]
    detail = []
    if message:
        detail.append("京东报错=" + message)
    if raw_payload_snippet and raw_payload_snippet != "{}":
        detail.append("原始响应=" + raw_payload_snippet)
    if exchange_error:
        detail.append("PT exchange=" + exchange_error)
    suffix = "；" + "；".join(detail) if detail else ""
    raise RuntimeError(
        (message or "login_lt 未返回 pt_key/pt_pin 或可用 ACRJUrl") + suffix,
        risk_url if risk_url else None,
    ) if risk_url else RuntimeError(
        (message or "login_lt 未返回 pt_key/pt_pin 或可用 ACRJUrl") + suffix
    )


# ========== 京东 wskey → cookie 转换（新增）==========

def wskey_to_cookie(wskey: str) -> Tuple[str, str]:
    """
    使用京东 wskey 换取 pt_key/pt_pin cookie（**带活性校验**）。

    wskey 是京东 APP 登录后的长期令牌，格式形如 "wskey=AAJ...;pin=..."。
    链路：genToken（带 sign，Cookie 必须同时含 wskey= 和 pin=）→ tokenKey → appjmp → pt_key。

    重要：**过期 wskey 时京东会返回 `pt_key=...fake...` 的假 key**，本函数会额外做一次
    用户信息活性校验；只有真正有效才返回，否则抛错，便于上层明确提示"验证失败"。
    """
    wskey = str(wskey or "").strip()
    if not wskey:
        raise ValueError("wskey 不能为空")

    t0 = time.monotonic()
    tried = []
    for name, fn in (("genToken", _wskey_genToken_to_cookie), ("qrlogin", _wskey_qrlogin_to_cookie)):
        try:
            cookie = fn(wskey)
        except Exception as exc:
            tried.append(f"{name}: {exc}")
            continue
        if not cookie:
            tried.append(f"{name}: 未返回 cookie")
            continue
        if "fake" in cookie.lower():
            tried.append(f"{name}: 京东返回了 fake pt_key（wskey 已失效）")
            continue
        if not _jd_cookie_alive(cookie):
            tried.append(f"{name}: 换出的 cookie 活性校验失败")
            continue
        pin = cookie_pin(cookie)
        _diag(f"✅ {name} 成功且活性通过，pt_key类型={pt_key_type(cookie)}，用时{time.monotonic()-t0:.1f}s")
        return cookie, pin

    raise RuntimeError("wskey 无效或已失效（换不出可用 cookie）：" + "；".join(tried))


def _wskey_genToken_to_cookie(wskey: str) -> str:
    """
    策略 1：genToken（**带 APP 签名**，必需）→ tokenKey → appjmp → pt_key/pt_pin。

    注意：不带 sign 会得到 {"code":"1","echo":"no access"}；凭证无效时 JD 返回
    tokenKey="xxx"（失效哨兵），此处按失败处理。
    """
    suid = "".join(str(uuid.uuid4()).split("-"))[16:]
    buid = _jd_b64e(suid)
    st = round(time.time() * 1000)
    sv = random.choice(["102", "111", "120"])
    # sign 必须用与下面发送的同一组 suid/st/sv
    sign = _jd_gen_sign("genToken", JD_GENTOKEN_BODY, suid, "android", "11.1.4", st, sv)
    ep = json.dumps({
        "hdid": "JM9F1ywUPwflvMIpYPok0tt5k9kW4ArJEU3lfLhxBqw=", "ts": st, "ridx": -1,
        "cipher": {"area": "CV8yEJUzXzU0CNG0XzK=", "d_model": "JWunCVVidRTr", "wifiBssid": "dW5hbw93bq==",
                   "osVersion": "CJS=", "d_brand": "WQvrb21f", "screen": "CJuyCMenCNq=",
                   "uuid": buid, "aid": buid, "openudid": buid},
        "ciphertype": 5, "version": "1.2.0", "appname": "com.jingdong.app.mall",
    }).replace(" ", "")
    params = _jd_classic_params(suid, ep, st, sv, sign)
    form_data = "body=" + urllib.parse.quote(JD_GENTOKEN_BODY, safe="") + "&"
    headers = {
        "User-Agent": _jd_app_ua(st, buid, buid),
        "Cookie": _wskey_cookie_header(wskey),
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "charset": "UTF-8",
        "Accept-Encoding": "br,gzip,deflate",
        "Accept": "*/*",
    }

    session = CurlSession(impersonate="chrome120")
    try:
        resp = session.post(
            "https://api.m.jd.com/client.action",
            params=params,
            headers=headers,
            data=form_data,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
    except Exception as exc:
        _diag(f"  genToken 请求异常: {exc}")
        return ""

    _diag(f"  genToken HTTP {resp.status_code}, body_len={len(resp.content)}")

    result = parse_jsonish(resp.text)
    token_key = str(result.get("tokenKey") or "").strip()
    if not token_key or token_key == "xxx":
        _diag(f"  genToken 未返回有效 tokenKey（{token_key or '空'}）：{resp.text[:200]}")
        return ""
    _diag(f"  genToken 拿到 tokenKey={token_key[:12]}…，走 appjmp 换 cookie")
    return _wskey_tokenKey_jump(session, token_key, wskey)


def _wskey_tokenKey_jump(session: CurlSession, token_key: str, wskey: str) -> str:
    """
    用 tokenKey 走京东 appjmp 换出 pt_key/pt_pin（经典链路 un.m.jd.com/cgi-bin/app/appjmp）。
    """
    headers = {
        "User-Agent": _jd_app_ua(round(time.time() * 1000), "x", "x"),
        "x-requested-with": "com.jingdong.app.mall",
    }
    current = "https://un.m.jd.com/cgi-bin/app/appjmp?" + urllib.parse.urlencode(
        {"tokenKey": token_key, "to": JD_APPJMP_TO}
    )
    for hop in range(4):
        try:
            resp = session.get(current, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except Exception as exc:
            _diag(f"  appjmp 请求异常: {exc}")
            break
        _diag(f"  appjmp[{hop}] HTTP {resp.status_code}")
        cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
        cookie = normalize_pt_cookie(cookie_str) or cookie_from_headers(dict(resp.headers)) or normalize_pt_cookie(resp.text)
        if cookie:
            return cookie
        location = resp.headers.get("Location") or resp.headers.get("location") or ""
        if not location or resp.status_code not in {200, 301, 302, 303, 307, 308}:
            break
        current = urllib.parse.urljoin(current, location)
        if not jd_pt_allowed_redirect(current):
            break
    return ""



def _wskey_qrlogin_to_cookie(wskey: str) -> str:
    """
    策略 2：通过 wskey 模拟 JD 扫码登录换取 cookie。

    部分场景下 genToken 不可用时，可以通过带上 wskey cookie 直接请求
    JD 用户信息接口来激活 session 并获取 pt_key/pt_pin。
    """
    session = CookieOpener()

    # step 1: 先用 wskey 访问 JD 首页激活 cookie
    headers = {
        "User-Agent": UA_DEFAULT,
        "Cookie": _wskey_cookie_header(wskey),
    }

    status, response_headers, raw = request_text(
        "GET", "https://home.m.jd.com/myJd/newhome.action",
        headers=headers, opener=session,
    )

    _diag(f"  qrLogin step1 home HTTP {status}")

    # step 2: 检查是否已经拿到了 pt_key/pt_pin
    cookie = normalize_pt_cookie(session.cookie_jar)
    if cookie:
        return cookie
    cookie = cookie_from_headers(response_headers)
    if cookie:
        return cookie

    # step 3: 尝试访问 myJd 接口
    # 注意：手动设置的 Cookie header 不会写入 cookie_jar，
    # 因此每个请求都必须显式携带 wskey，否则等于裸请求
    status2, response_headers2, raw2 = request_text(
        "GET", "https://wq.jd.com/user/info/QueryJDUserInfo?sceneval=2",
        headers={
            "User-Agent": UA_DEFAULT,
            "Referer": "https://home.m.jd.com/",
            "Cookie": _wskey_cookie_header(wskey),
        },
        opener=session,
    )

    _diag(f"  qrLogin step2 QueryJDUserInfo HTTP {status2}")

    cookie = normalize_pt_cookie(session.cookie_jar)
    if not cookie:
        cookie = cookie_from_headers(response_headers2)

    # step 4: 尝试从响应中解析
    if not cookie:
        result = parse_jsonish(raw2)
        cookie = cookie_from_payload(result)

    return cookie


# ========== Flask 应用 ==========

app = Flask(__name__)


def require_token(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not AUTORPOST_TOKEN:
            return jsonify({"status": "error", "message": "AUTORPOST_TOKEN 未配置"}), 500
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"status": "error", "message": "缺少 Bearer token"}), 401
        token = auth_header[7:]
        if not hmac.compare_digest(token, AUTORPOST_TOKEN):
            return jsonify({"status": "error", "message": "无效的 token"}), 403
        return f(*args, **kwargs)
    return decorated


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# ---- 原有端点：code 登录 ----

@app.route("/api/jd-check", methods=["POST"])
@require_token
def jd_check():
    body = request.get_json(silent=True) or {}
    yyb_server_raw = (body.get("yyb_server") or "").strip()
    ref = (body.get("ref") or "").strip()
    app_id = (body.get("app_id") or "").strip() or None

    if not yyb_server_raw:
        return jsonify({"status": "error", "message": "缺少 yyb_server 参数"}), 400
    if not ref:
        return jsonify({"status": "error", "message": "缺少 ref 参数"}), 400

    try:
        yyb_server = normalize_yyb_server(yyb_server_raw)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    try:
        cookie, risk_url = attempt_code_login(yyb_server, ref, full=False)
        if cookie:
            pin = cookie_pin(cookie)
            return jsonify({
                "status": "ok",
                "jd_cookie": cookie,
                "risk_url": None,
                "message": "成功获取京东 cookie",
                "pt_pin": pin,
            })
        return jsonify({
            "status": "error",
            "jd_cookie": "",
            "risk_url": risk_url,
            "message": "未能获取 cookie",
            "pt_pin": "",
        }), 500
    except RuntimeError as exc:
        exc_args = exc.args
        risk_url = None
        message = str(exc)
        if len(exc_args) > 1 and exc_args[1]:
            risk_url = exc_args[1]
        if risk_url or "ACRJUrl" in message or "风险" in message:
            return jsonify({
                "status": "risk",
                "jd_cookie": "",
                "risk_url": risk_url or "",
                "message": message,
                "pt_pin": "",
            })
        if "登录缓存已过期" in message or "login_buffer expired" in message:
            return jsonify({
                "status": "risk",
                "jd_cookie": "",
                "risk_url": "",
                "message": message,
                "pt_pin": "",
            })
        return jsonify({
            "status": "error",
            "jd_cookie": "",
            "risk_url": "",
            "message": message,
            "pt_pin": "",
        }), 500
    except Exception as exc:
        return jsonify({
            "status": "error",
            "jd_cookie": "",
            "risk_url": "",
            "message": f"内部错误：{exc}",
            "pt_pin": "",
        }), 500


# ---- 新增端点：wskey → cookie ----

@app.route("/api/jd-wskey", methods=["POST"])
@require_token
def jd_wskey():
    """
    京东 wskey 转 cookie 接口。

    请求体:
        {"wskey": "AAJ..."}

    响应:
        {"status": "ok", "jd_cookie": "pt_key=...;pt_pin=...;", "pt_pin": "...", "message": "..."}
        {"status": "error", "jd_cookie": "", "message": "..."}
    """
    body = request.get_json(silent=True) or {}
    wskey = (body.get("wskey") or "").strip()

    if not wskey:
        return jsonify({
            "status": "error",
            "jd_cookie": "",
            "message": "缺少 wskey 参数（登记格式：pin=你的pin;wskey=AAJ...，在京东APP抓包或 Stream 获取）",
            "pt_pin": "",
        }), 400

    try:
        cookie, pin = wskey_to_cookie(wskey)
        return jsonify({
            "status": "ok",
            "jd_cookie": cookie,
            "risk_url": None,
            "message": "wskey 转 cookie 成功",
            "pt_pin": pin,
            "pt_key_type": pt_key_type(cookie),
        })
    except ValueError as exc:
        return jsonify({
            "status": "error",
            "jd_cookie": "",
            "risk_url": "",
            "message": str(exc),
            "pt_pin": "",
        }), 400
    except RuntimeError as exc:
        return jsonify({
            "status": "error",
            "jd_cookie": "",
            "risk_url": "",
            "message": str(exc),
            "pt_pin": "",
        }), 500
    except Exception as exc:
        return jsonify({
            "status": "error",
            "jd_cookie": "",
            "risk_url": "",
            "message": f"内部错误：{exc}",
            "pt_pin": "",
        }), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    try:
        from waitress import serve
        print(f"jdback 服务启动 (waitress)，端口 {port}")
        serve(app, host="0.0.0.0", port=port)
    except ImportError:
        print(f"jdback 服务启动 (Flask dev)，端口 {port}")
        app.run(host="0.0.0.0", port=port)
