import requests
import urllib3
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import log_info, log_error
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_token(switch_ip, username, password, session, verify_ssl, version):
    try:
        base_url = f"https://{switch_ip}/rest/v{version}/login"
        headers = {
            "accept": "*/*",
            "x-use-csrf-token": "true"
        }
        # Prefer form data over query string to avoid credentials in URLs.
        payload = {"username": username, "password": password}
        response = session.post(base_url, headers=headers, data=payload, verify=verify_ssl, timeout=10)
        if response.status_code in (404, 405, 415):
            encoded_username = quote(username)
            encoded_password = quote(password)
            url = f"{base_url}?username={encoded_username}&password={encoded_password}"
            response = session.post(url, headers=headers, data="", verify=verify_ssl, timeout=10)
        response.raise_for_status()
        csrf_token = response.headers.get("x-csrf-token")
        session.headers.update({"x-csrf-token": csrf_token})
        return session
    except requests.exceptions.SSLError:
        log_error(f"SSL verification failed for {switch_ip} during token retrieval.")
        return "SSLERROR"
    except requests.exceptions.Timeout:
        log_error(f"Timeout connecting to {switch_ip} during token retrieval.")
        return "TIMEOUT"
    except Exception as e:
        # Redact password from the log message
        log_error(f"Failed to get token for {switch_ip} with username '{username}': Authentication failed or API error.")
        return None

def get_hostname(switch_ip, session, version, verify_ssl):
    try:
        url = f"https://{switch_ip}/rest/v{version}/system?attributes=hostname"
        headers = {"accept": "application/json"}
        response = session.get(url, headers=headers, verify=verify_ssl, timeout=10)
        response.raise_for_status()
        return response.json().get("hostname", "Unknown")
    except Exception as e:
        log_error(f"Failed to get hostname from {switch_ip}: {e}")
        return "Unknown"

def get_switch_info(switch_ip, endpoint, session, version, depth, selector, verify_ssl, attributes=None):
    try:
        
        url = f"https://{switch_ip}/rest/v{version}/{endpoint.removeprefix('/')}"
        params = []
        if depth and int(depth) > 1:
            params.append(f"depth={depth}")
        if selector:
            params.append(f"selector={selector}")
        if attributes:
            # attributes can be a CSV string or list/tuple
            if isinstance(attributes, (list, tuple)):
                attrs = ",".join(str(a).strip() for a in attributes if str(a).strip())
            else:
                attrs = str(attributes).strip()
            if attrs:
                params.append(f"attributes={attrs}")
        if params:
            url += "?" + "&".join(params)

        headers = {"accept": "application/json"}
        log_info(f"Getting {url}")
        response = session.get(url, headers=headers, verify=verify_ssl, timeout=30)
        response.raise_for_status()
        return response.json()

    except Exception as e:
        log_error(f"Failed to get info for {switch_ip}: {e}")
        return {"error": str(e)}

def logout(switch_ip, session, verify_ssl, version):
    try:
        logout_url = f"https://{switch_ip}/rest/v{version}/logout"
        session.post(logout_url, verify=verify_ssl, timeout=10)
    except:
        pass

def run_api_calls(switches, username, password, endpoint, version, depth, selector, verify_ssl, on_result, on_progress, stop_event, concurrency=5, attributes=None):
    log_info("Running API calls...")
    if not switches:
        log_info("No switches provided. Nothing to do.")
        if on_progress:
            on_progress(0, 0)
        return

    def task(switch):
        if stop_event.is_set():
            return switch, {"error": "Operation stopped by user"}, "Stopped"

        session = requests.Session()
        session = get_token(switch, username, password, session, verify_ssl, version)
        if session == "TIMEOUT":
            return switch, {"error": "Connection timed out"}, "Unknown"
        if session == "SSLERROR":
            return switch, {"error": "SSL verification failed"}, "Unknown"
        if not session:
            return switch, {"error": "Authentication failed"}, "Unknown"
        if stop_event.is_set(): # Check again before making hostname call
            logout(switch, session, verify_ssl, version)
            return switch, {"error": "API call stopped by user"}, "Stopped"
        
        hostname = get_hostname(switch, session, version, verify_ssl)


        if stop_event.is_set(): # Check again before making info call
            logout(switch, session, verify_ssl, version)
            return switch, {"error": "API call stopped by user"}, "Stopped"
                
        data = get_switch_info(switch, endpoint, session, version, depth, selector, verify_ssl, attributes)
        logout(switch, session, verify_ssl, version)
        session.close()
        return switch, data, hostname

    completed_futures_count = 0
    with ThreadPoolExecutor(max_workers=min(concurrency, len(switches))) as executor:
        futures = {executor.submit(task, s): s for s in switches}
        
        # Iterate over futures as they complete
        for future in as_completed(futures):
            if stop_event.is_set():
                log_info("Stop event detected, cancelling remaining futures.")
                for f in futures:
                    f.cancel() # Attempt to cancel remaining futures
                break # Exit the loop

            try:
                switch, data, hostname = future.result()
                completed_futures_count += 1
                if on_result:
                    on_result(switch, data, hostname)
                if on_progress:
                    on_progress(completed_futures_count, len(switches))
            except Exception as exc:
                log_error(f"{futures[future]} generated an exception: {exc}")
                completed_futures_count += 1 # Still count it for progress
                if on_progress:
                    on_progress(completed_futures_count, len(switches))

    log_info("API calls finished.")
