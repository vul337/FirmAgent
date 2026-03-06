#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import requests
import logging
import time
import os
from urllib.parse import urljoin
import argparse
from typing import List, Dict, Any, Tuple


class APIFuzzer:
    def __init__(self, base_url: str, json_file: str, delay: float = 1.0, target_host: str = "", taint_tag: str = "taint_tag"):
        """
        Initialize API Fuzzer.
        :param base_url: Base API URL (e.g., http://192.168.0.1)
        :param json_file: Path to the JSON file containing API definitions
        :param delay: Delay between requests (seconds)
        """
        self.base_url = base_url.rstrip('/')
        self.json_file = json_file
        self.delay = delay
        self.target_host = target_host
        self.taint_tag = taint_tag
        self.session = requests.Session()

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('fuzzing_results.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _resolve_result_path(self) -> str:
        """Resolve result output path; prefer JSON sibling dir, fallback to cwd."""
        input_dir = os.path.dirname(os.path.abspath(self.json_file))
        preferred = os.path.join(input_dir, "result.json")

        try:
            os.makedirs(input_dir, exist_ok=True)
            with open(preferred, 'w', encoding='utf-8') as f:
                json.dump([], f)
            return preferred
        except Exception as e:
            self.logger.warning(f"Cannot write result.json next to input JSON: {e}")

        fallback = os.path.join(os.getcwd(), "result.json")
        with open(fallback, 'w', encoding='utf-8') as f:
            json.dump([], f)
        self.logger.warning(f"Fallback result path: {fallback}")
        return fallback

    def _flush_results(self, result_path: str, results: List[Dict[str, Any]]) -> None:
        with open(result_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

    def load_targets(self) -> Tuple[List[str], List[str]]:
        """Load target APIs and parameters from JSON file.

        Preferred format:
        {
          "api_endpoints": [...],
          "para": [...]
        }
        """
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            api_endpoints: List[str] = []
            parameters: List[str] = []

            if isinstance(data, dict):
                raw_apis = data.get("api_endpoints", [])
                raw_para = data.get("para", [])
                if isinstance(raw_apis, list):
                    api_endpoints = [str(item).strip() for item in raw_apis if str(item).strip()]
                if isinstance(raw_para, list):
                    parameters = [str(item).strip() for item in raw_para if str(item).strip()]

            if not api_endpoints and isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("api_url"):
                        api_endpoints.append(str(item["api_url"]).strip())

            if not api_endpoints:
                self.logger.error("No api_endpoints found in input JSON")
                return [], []

            # 去重并保持顺序
            dedup_apis = list(dict.fromkeys(api_endpoints))
            dedup_para = list(dict.fromkeys(parameters))
            return dedup_apis, dedup_para
        except Exception as e:
            self.logger.error(f"Failed to load JSON file: {e}")
            return [], []

    def build_taint_payload(self, parameters: List[str], taint_param: str) -> Dict[str, str]:
        """Build payload with all parameters present; only one parameter is tainted per request."""
        payload = {param: "" for param in parameters}
        if taint_param in payload:
            payload[taint_param] = self.taint_tag
        return payload

    def send_request(self, api_url: str, payload: Dict[str, str], method: str = "POST") -> Dict[str, Any]:
        """Send HTTP request with one API + all parameters filled by taint_tag."""
        url = urljoin(self.base_url + '/', api_url.lstrip('/'))
        method_upper = method.upper()
        # Supplementary authentication information
        headers = {
            "Host": self.target_host if self.target_host else self.base_url.replace("http://", "").replace("https://", ""),
            "Cache-Control": "max-age=0",
            "Accept-Language": "zh-CN",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Connection": "keep-alive"
        }

        try:
            if method_upper == 'GET':
                response = self.session.get(url, params=payload, headers=headers, timeout=10, verify=False)
            elif method_upper == 'POST':
                response = self.session.post(url, json=payload, headers=headers, timeout=10, verify=False)
            elif method_upper == 'PUT':
                response = self.session.put(url, json=payload, headers=headers, timeout=10, verify=False)
            elif method_upper == 'DELETE':
                response = self.session.delete(url, json=payload, headers=headers, timeout=10, verify=False)
            else:
                response = self.session.request(method_upper, url, json=payload, headers=headers, timeout=10, verify=False)

            return {
                'url': url,
                'method': method_upper,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'content_length': len(response.content),
                'headers': dict(response.headers),
                'content': response.text[:1000]
            }

        except requests.exceptions.RequestException as e:
            return {
                'error': str(e),
                'status_code': None,
                'response_time': None
            }

    def analyze_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze response for basic anomaly signals."""
        analysis = {
            'potential_issue': False,
            'issue_type': None,
            'evidence': []
        }

        if 'error' in response_data:
            analysis['evidence'].append(f"Request error: {response_data['error']}")
            analysis['potential_issue'] = True
            analysis['issue_type'] = 'RequestError'
            return analysis

        status_code = response_data.get('status_code')
        response_time = response_data.get('response_time', 0)

        if status_code in [500, 502, 503]:
            analysis['potential_issue'] = True
            analysis['issue_type'] = 'ServerError'
            analysis['evidence'].append(f'Status code: {status_code}')

        if response_time and response_time > 3:
            analysis['potential_issue'] = True
            if not analysis['issue_type']:
                analysis['issue_type'] = 'SlowResponse'
            analysis['evidence'].append(f'Long response time: {response_time}s')

        return analysis

    def fuzz_api(self, api_url: str, parameters: List[str], method: str) -> List[Dict[str, Any]]:
        """For one API, iterate all parameters and taint one parameter per request."""
        self.logger.info(f"Testing API: {api_url}")
        results: List[Dict[str, Any]] = []

        if not parameters:
            payload = {}
            response_data = self.send_request(api_url, payload, method)
            analysis = self.analyze_response(response_data)
            result = {
                'api_url': api_url,
                'method': method.upper(),
                'taint_param': None,
                'taint_tag': self.taint_tag,
                'post_payload': payload,
                'response': response_data,
                'analysis': analysis
            }
            results.append(result)
            time.sleep(self.delay)
            return results

        for param in parameters:
            payload = self.build_taint_payload(parameters, param)
            response_data = self.send_request(api_url, payload, method)
            analysis = self.analyze_response(response_data)

            result = {
                'api_url': api_url,
                'method': method.upper(),
                'taint_param': param,
                'taint_tag': self.taint_tag,
                'post_payload': payload,
                'response': response_data,
                'analysis': analysis
            }
            results.append(result)

            if analysis['potential_issue']:
                self.logger.warning(f"[!] Potential issue on {api_url} param {param}: {analysis['issue_type']}")
                self.logger.warning(f"Evidence: {analysis['evidence']}")

            time.sleep(self.delay)

        return results

    def run_fuzzing(self) -> None:
        """Run taint-tag requests on all APIs.

        Logic:
        - pick one URL
        - iterate all parameters, taint one parameter per request
        - then move to next URL
        """
        result_path = self._resolve_result_path()
        self.logger.info(f"Result file will be written to: {result_path}")

        api_endpoints, parameters = self.load_targets()
        all_results: List[Dict[str, Any]] = []

        if not api_endpoints:
            self.logger.error("No API endpoints found")
            self._flush_results(result_path, all_results)
            return

        if not parameters:
            self.logger.warning("No parameters found, requests will carry empty JSON payload")

        for i, api_url in enumerate(api_endpoints, 1):
            self.logger.info(f"Progress: {i}/{len(api_endpoints)}")
            try:
                per_api_results = self.fuzz_api(api_url, parameters, self.method)
                all_results.extend(per_api_results)
                self._flush_results(result_path, all_results)
            except Exception as e:
                self.logger.error(f"Error fuzzing {api_url}: {e}")
                self._flush_results(result_path, all_results)

        self._flush_results(result_path, all_results)
        self.logger.info(f"Saved request packets to: {result_path}")

        self.logger.info("Fuzzing completed!")

    @property
    def method(self) -> str:
        return getattr(self, "_method", "POST")

    @method.setter
    def method(self, value: str) -> None:
        self._method = (value or "POST").upper()


def main():
    parser = argparse.ArgumentParser(description="API Fuzzer Tool")
    parser.add_argument("--json-file", required=True, help="Path to the JSON file containing API definitions")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--host", required=True, help="Host header value (IP or domain)")
    parser.add_argument("--method", default="POST", choices=["GET", "POST", "PUT"], help="HTTP method used for all API requests")
    parser.add_argument("--taint-tag", default="taint_tag", help="Tag string injected to every parameter")
    args = parser.parse_args()

    if args.host.startswith("http://") or args.host.startswith("https://"):
        base_url = args.host
        host_header = args.host.replace("http://", "").replace("https://", "")
    else:
        base_url = f"http://{args.host}"
        host_header = args.host

    fuzzer = APIFuzzer(base_url, args.json_file, args.delay, host_header, args.taint_tag)
    fuzzer.method = args.method
    fuzzer.run_fuzzing()


if __name__ == '__main__':
    main()
