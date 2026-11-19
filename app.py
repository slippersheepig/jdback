#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jdback — 京东小程序 code 登录 Flask Web 服务。

端点:
  POST /api/jd-check    — 小程序 code 登录
"""

from __future__ import annotations

import functools
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
            if opener is not None and hasattr(opener, "cookie_jar"):
                try:
                    opener.cookie_jar.extract_cookies(resp, request)
                except Exception:
                    pass
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
        if opener is not None and hasattr(opener, "cookie_jar"):
            try:
                opener.cookie_jar.extract_cookies(exc, request)
            except Exception:
                pass
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
    if not isinstance(payload, dict):
        return ""
    ret_code = payload.get("retCode", payload.get("retcode"))
    if ret_code in (0, "0"):
        return ""
    value = nested_value(
        payload,
        (
            "errmsg", "errMsg", "message", "msg", "error",
            "retmsg", "retMessage", "returnMsg", "return_msg",
            "err_msg", "desc", "description",
            "reason", "detail",
        ),
    )
    if isinstance(value, (dict, list)):
        if isinstance(value, dict):
            inner = nested_value(value, ("msg", "message", "errmsg", "errMsg", "error", "desc"))
            if inner and isinstance(inner, str):
                val_str = inner.strip()[:300]
                return "" if val_str.lower() == "login success" else val_str
        return json.dumps(value, ensure_ascii=False)[:300]
    val_str = str(value or "").strip()[:300]
    return "" if val_str.lower() == "login success" else val_str


def request_json(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    opener: Optional[CookieOpener] = None,
    yyb_server: str = "",
    api_token: str = "",
) -> Dict[str, Any]:
    merged_headers = dict(headers or {})
    token = api_token or YYB_API_TOKEN
    if token and yyb_server and url.startswith(yyb_server):
        merged_headers.setdefault("Authorization", f"Bearer {token}")
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

def normalize_pt_cookie(cookie: Any, fallback_pin: str = "") -> str:
    if isinstance(cookie, CookieJar):
        values: Dict[str, str] = {}
        for item in cookie:
            if item.name in {"pt_key", "pt_pin", "pin", "jdpin"} and item.value:
                values[item.name] = str(item.value)
        pt_key = values.get("pt_key")
        pt_pin = values.get("pt_pin") or values.get("pin") or values.get("jdpin") or fallback_pin
        if pt_key and pt_pin:
            return f"pt_key={pt_key};pt_pin={pt_pin};"
        return ""

    text = str(cookie or "")
    key_match = re.search(r"(?:^|[;?,\s])pt_key=([^;?,\s]+)", text)
    pin_match = re.search(r"(?:^|[;?,\s])(?:pt_pin|pin|jdpin)=([^;?,\s]+)", text)
    if key_match:
        pt_key = key_match.group(1)
        pt_pin = pin_match.group(1) if pin_match else fallback_pin
        if pt_pin:
            return f"pt_key={pt_key};pt_pin={pt_pin};"
    return ""


def cookie_from_headers(headers: Dict[str, Any], fallback_pin: str = "") -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() not in {"set-cookie", "set-cookie2"}:
            continue
        cookie = normalize_pt_cookie(str(value), fallback_pin=fallback_pin)
        if cookie:
            return cookie
    return ""


def cookie_from_payload(payload: Any, fallback_pin: str = "") -> str:
    pt_key = nested_string(payload, ("pt_key", "ptKey"))
    pt_pin = nested_string(payload, ("pt_pin", "ptPin", "pin", "jdpin")) or fallback_pin
    if pt_key and pt_pin:
        return normalize_pt_cookie(f"pt_key={pt_key};pt_pin={pt_pin};", fallback_pin=fallback_pin)
    return normalize_pt_cookie(str(payload or ""), fallback_pin=fallback_pin)


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
    match = re.search(r"(?:^|[;,\s])(?:pt_pin|pin|jdpin)=([^;,\s]+)", pure or cookie)
    return match.group(1) if match else ""


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
    api_token: str = "",
) -> str:
    request_app_id = str(app_id or JD_APPID).strip()
    payload = request_json(
        "POST",
        f"{yyb_server}/wxapp/getCode",
        data={"ref": ref, "app_id": request_app_id},
        yyb_server=yyb_server,
        api_token=api_token,
    )
    result = unwrap_service_payload(payload)
    code = nested_string(result, ("wxCode", "wx_code", "jsCode", "jscode", "code"))
    if len(code) < 8 or code in {"0", "200", "201"}:
        raise RuntimeError("应用宝 getCode 未返回有效一次性 code")
    return code


def get_yyb_user_info(yyb_server: str, ref: str, api_token: str = "") -> Dict[str, str]:
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
        api_token=api_token,
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


def get_yyb_h5_code(
    yyb_server: str,
    ref: str,
    app_id: str,
    redirect_uri: str,
    scope: str = "snsapi_userinfo",
    state: str = "STATE",
    api_token: str = "",
) -> str:
    """通过 YYB H5 网页授权通道（命令 1254 /wx/h5code）获取公众号/网页 OAuth2 code。
    绝不向小程序接口 /wxapp/getCode（命令 1029）发送非小程序 AppID，避免微信撤销应用宝授权。
    """
    request_app_id = str(app_id or JD_PT_APPID).strip()
    scopes_to_try = [scope] if scope == "snsapi_base" else [scope, "snsapi_base"]
    last_err: Optional[Exception] = None
    for try_scope in scopes_to_try:
        for path in ("/wx/h5code", "/wxapp/getH5Code"):
            try:
                payload = request_json(
                    "POST",
                    f"{yyb_server}{path}",
                    data={
                        "ref": ref,
                        "app_id": request_app_id,
                        "payload": {
                            "redirect_uri": redirect_uri,
                            "scope": try_scope,
                            "state": state,
                        },
                    },
                    yyb_server=yyb_server,
                    api_token=api_token,
                )
                result = unwrap_service_payload(payload)
                code = nested_string(result, ("wxCode", "wx_code", "jsCode", "jscode", "code"))
                if len(code) >= 8 and code not in {"0", "200", "201"}:
                    return code
                last_err = RuntimeError("应用宝 getH5Code 未返回有效一次性 code")
                break
            except Exception as exc:
                last_err = exc
                if "HTTP 404" in str(exc):
                    continue
                break
    raise RuntimeError(f"H5 OAuth 取码失败：{last_err}")


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


def exchange_pt_cookie(yyb_server: str, ref: str, api_token: str = "") -> str:
    """通过京东 H5 微信登录页 -> 获取带 wxlsid 的回调 -> YYB H5 OAuth(1254) 取码 -> 回调 wxlogincenter 换取 pt_key"""
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
    state = oauth_query.get("state", ["STATE"])[0] or "STATE"
    scope = oauth_query.get("scope", ["snsapi_userinfo"])[0] or "snsapi_userinfo"
    if not redirect_uri or not state:
        raise RuntimeError("JD PT OAuth 缺少 redirect_uri/state")

    pt_code = get_yyb_h5_code(
        yyb_server,
        ref,
        app_id=JD_PT_APPID,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        api_token=api_token,
    )

    callback = urllib.parse.urlparse(redirect_uri)
    callback_query = urllib.parse.parse_qsl(callback.query, keep_blank_values=True)
    callback_query.extend([("code", pt_code), ("state", state)])
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


def activate_jd_session(session: CookieOpener, pin: str = "") -> str:
    """通过已建立的微信小程序会话（包含 wq_uin, sfstoken, pin）请求京东页面尝试激活 pt_key"""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 "
            "MicroMessenger/8.0.49 NetType/WIFI"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": "https://wq.jd.com/",
    }
    urls = [
        "https://wq.jd.com/passport/LoginRedirect?url=https%3A%2F%2Fmy.m.jd.com%2F",
        "https://home.m.jd.com/myJd/newhome.action",
    ]
    for start_url in urls:
        current = start_url
        for hop in range(8):
            if not allowed_jd_url(current):
                break
            try:
                status, resp_headers, raw = request_text("GET", current, headers=headers, opener=session)
            except Exception as e:
                _diag(f"activate_jd_session 请求异常 [{hop}] {current}: {e}")
                break
            ck = normalize_pt_cookie(session.cookie_jar, fallback_pin=pin)
            if not ck:
                ck = cookie_from_headers(resp_headers, fallback_pin=pin)
            if not ck:
                ck = normalize_pt_cookie(raw, fallback_pin=pin)
            if ck:
                _diag(f"activate_jd_session 成功于 [{hop}] {current} 获取到 pt_key")
                return ck
            location = resp_headers.get("Location") or resp_headers.get("location") or ""
            if not location and status == 200:
                location = jd_pt_html_redirect(current, raw)
            if not location or status not in {200, 301, 302, 303, 307, 308}:
                break
            current = urllib.parse.urljoin(current, location)
            time.sleep(0.3)
    return normalize_pt_cookie(session.cookie_jar, fallback_pin=pin)


def attempt_code_login(
    yyb_server: str,
    ref: str,
    full: bool = False,
    api_token: str = "",
    existing_session: Optional[CookieOpener] = None,
) -> Tuple[str, Optional[str]]:
    label = "full" if full else "code-only"
    t0 = time.monotonic()
    session = existing_session or CookieOpener()
    code = get_yyb_code(yyb_server, ref, api_token=api_token)
    user_info = get_yyb_user_info(yyb_server, ref, api_token=api_token) if full else None
    _diag(f"[{label}] 已取得 " + ("code+userInfo" if full else "code") + f"，用时{time.monotonic()-t0:.1f}s")
    payload = call_login_lt(session, code, user_info)
    info = login_info(payload)
    pin = nested_string(info, ("pin", "jdpin"))
    first_acrj = nested_string(info, ("ACRJUrl", "acrjUrl"))
    if first_acrj:
        _diag(f"[{label}] login_lt 直接返回风险挑战：{risk_fingerprint(first_acrj)}")
    else:
        _diag(f"[{label}] login_lt 未触发风险挑战（retMsg={response_message(payload) or '(空)'}）")
    cookie = normalize_pt_cookie(session.cookie_jar, fallback_pin=pin)
    if not cookie:
        cookie = normalize_pt_cookie(str(getattr(session, "last_response_cookie", "") or ""), fallback_pin=pin)
    if not cookie:
        cookie = cookie_from_payload(payload, fallback_pin=pin)
    if not cookie and first_acrj:
        cookie = follow_server_refresh(session, payload)
    if cookie:
        _diag(f"[{label}] ✅ login_lt/follow_refresh 直接拿到 pt_key，总用时{time.monotonic()-t0:.1f}s")
        return normalize_pt_cookie(cookie, fallback_pin=pin), None

    # code-only 阶段如果未直接拿到 pt_key，不要污染 session，也不要提前返回不含 pt_key 的 sfstoken/pin，
    # 立即交由外层 login_via_code 升级为 full=True (携带 getUserInfo 全参数 + 已建立的 session Cookie) 重试！
    if not full:
        risk_url = first_acrj or nested_string(login_info(payload), ("ACRJUrl", "acrjUrl"))
        msg = response_message(payload) or "code-only 未下发 pt_key"
        raise RuntimeError(msg, risk_url if risk_url else None) if risk_url else RuntimeError(msg)

    # full=True 阶段：如果已建立会话但首次全参数调用仍未签发 pt_key，尝试会话激活及 H5 PT OAuth(1254)
    activated = activate_jd_session(session, pin=pin)
    if activated:
        _diag(f"[{label}] ✅ 会话激活拿到 pt_key，总用时{time.monotonic()-t0:.1f}s")
        return normalize_pt_cookie(activated, fallback_pin=pin), None

    exchange_error = ""
    try:
        pt_cookie = exchange_pt_cookie(yyb_server, ref, api_token=api_token)
        if pt_cookie:
            _diag(f"[{label}] ✅ H5 PT OAuth(1254) 链拿到 pt_key，总用时{time.monotonic()-t0:.1f}s")
            return pt_cookie, None
    except Exception as exc:
        exchange_error = str(exc)
        _diag(f"[{label}] ⚠️ H5 PT OAuth(1254) 链跳过：{exchange_error}")

    _diag(f"[{label}] ❌ 全部手段均未拿到 pt_key，总用时{time.monotonic()-t0:.1f}s")
    risk_url = first_acrj or nested_string(login_info(payload), ("ACRJUrl", "acrjUrl"))
    message = response_message(payload)
    skey_present = bool(
        jar_get(session.cookie_jar, "wq_skey")
        or jar_get(session.cookie_jar, "skey")
        or nested_string(info, ("skey",))
        or jar_get(session.cookie_jar, "sfstoken")
    )
    detail = []
    if skey_present and not risk_url:
        detail.append("京东 login_lt 仅返回小程序会话(skey/sfstoken)而未签发主站 pt_key")
    if message:
        detail.append("京东报错=" + message)
    if exchange_error:
        detail.append("H5 OAuth=" + exchange_error)
    suffix = "；" + "；".join(detail) if detail else ""
    base_err = message or "京东未下发有效 pt_key/pt_pin"
    raise RuntimeError(
        base_err + suffix,
        risk_url if risk_url else None,
    ) if risk_url else RuntimeError(
        base_err + suffix
    )


def login_via_code(
    yyb_server: str,
    ref: str,
    api_token: str = "",
) -> Tuple[str, Optional[str]]:
    """优先尝试 code-only 静默登录，若未拿到 pt_key 则继承会话自动回退全参数(code+getUserInfo)及 H5 OAuth(1254) 重试"""
    session = CookieOpener()
    first_risk_url: Optional[str] = None
    try:
        cookie, risk_url = attempt_code_login(yyb_server, ref, full=False, api_token=api_token, existing_session=session)
        if normalize_pt_cookie(cookie):
            return normalize_pt_cookie(cookie), risk_url
        if risk_url and str(risk_url).strip():
            first_risk_url = str(risk_url).strip()
    except Exception as code_error:
        err_msg = str(code_error)
        if "登录缓存已过期" in err_msg or "login_buffer expired" in err_msg:
            raise
        if len(getattr(code_error, "args", ())) > 1 and code_error.args[1]:
            first_risk_url = str(code_error.args[1]).strip()
        _diag(f"code-only 静默登录未拿到 pt_key（{err_msg}），自动继承会话改用全参数新 code 重试")

    # 静默登录未拿到 pt_key，自动改用全参数（含 userInfo、signature、encryptedData）重试，并继承会话
    try:
        return attempt_code_login(yyb_server, ref, full=True, api_token=api_token, existing_session=session)
    except RuntimeError as full_error:
        if first_risk_url and (len(full_error.args) < 2 or not full_error.args[1]):
            raise RuntimeError(full_error.args[0], first_risk_url) from full_error
        raise


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
    api_token = (request.headers.get("X-YYB-API-Token") or body.get("api_token") or "").strip()

    if not yyb_server_raw:
        return jsonify({"status": "error", "message": "缺少 yyb_server 参数"}), 400
    if not ref:
        return jsonify({"status": "error", "message": "缺少 ref 参数"}), 400

    try:
        yyb_server = normalize_yyb_server(yyb_server_raw)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    try:
        cookie, risk_url = login_via_code(yyb_server, ref, api_token=api_token)
        if cookie:
            pin = cookie_pin(cookie)
            return jsonify({
                "status": "ok",
                "jd_cookie": cookie,
                "risk_url": None,
                "message": "成功获取京东 cookie",
                "pt_pin": pin,
            })
        if risk_url and str(risk_url).strip():
            return jsonify({
                "status": "risk",
                "jd_cookie": "",
                "risk_url": str(risk_url).strip(),
                "message": "京东返回风险认证挑战",
                "pt_pin": "",
            })
        return jsonify({
            "status": "error",
            "jd_cookie": "",
            "risk_url": "",
            "message": "未能获取 cookie",
            "pt_pin": "",
        }), 200
    except RuntimeError as exc:
        exc_args = exc.args
        risk_url = None
        message = str(exc)
        if len(exc_args) > 1 and exc_args[1]:
            risk_url = str(exc_args[1]).strip()
        # 仅当真正拿到了非空的 risk_url 时才返回 status: "risk"
        if risk_url:
            return jsonify({
                "status": "risk",
                "jd_cookie": "",
                "risk_url": risk_url,
                "message": message,
                "pt_pin": "",
            })
        if "登录缓存已过期" in message or "login_buffer expired" in message:
            return jsonify({
                "status": "error",
                "jd_cookie": "",
                "risk_url": "",
                "message": "应用宝账号登录缓存已过期，请重新扫码",
                "pt_pin": "",
            }), 409
        return jsonify({
            "status": "error",
            "jd_cookie": "",
            "risk_url": "",
            "message": message,
            "pt_pin": "",
        }), 200
    except Exception as exc:
        return jsonify({
            "status": "error",
            "jd_cookie": "",
            "risk_url": "",
            "message": f"内部错误：{exc}",
            "pt_pin": "",
        }), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    try:
        from waitress import serve
        print(f"jdback 服务启动 (waitress)，端口 {port}")
        serve(app, host="0.0.0.0", port=port)
    except ImportError:
        print(f"jdback 服务启动 (Flask dev)，端口 {port}")
        app.run(host="0.0.0.0", port=port)
