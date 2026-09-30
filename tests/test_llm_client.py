import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from conftest import requires_r2, valid_submission
from retriage.agent import Agent
from retriage.llm import LLMError, OpenAIChat


FAKE_KEY = "sk-" + "test-" + "SECRET"      # assembled at runtime so no secret-shaped literal sits in the source


class FakeServer:
    """Minimal OpenAI-compatible endpoint that replays queued (status, body) responses."""

    def __init__(self, responses):
        self.responses, self.requests = list(responses), []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                status, payload = outer.responses.pop(0)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/v1"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def tool_call_reply(name, args, cid="c1"):
    return (200, {"choices": [{"message": {"content": None, "tool_calls": [
        {"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}}]})


@pytest.fixture()
def server():
    servers = []
    def make(responses):
        s = FakeServer(responses)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()


@requires_r2
def test_agent_works_through_openai_compatible_client(server, toolbox):
    srv = server([tool_call_reply("get_binary_info", {}), tool_call_reply("submit_report", {"report": valid_submission()}, "c2")])
    llm = OpenAIChat(base_url=srv.url, api_key=FAKE_KEY, model="m")
    res = Agent(toolbox, llm, max_steps=5).run()
    assert res.status == "ok"
    first = srv.requests[0]
    assert first["path"].endswith("/chat/completions") and first["auth"] == "Bearer " + FAKE_KEY
    assert len(first["body"]["tools"]) == 14 and first["body"]["temperature"] == 0
    assert first["body"]["messages"][0]["role"] == "system"
    second_msgs = srv.requests[1]["body"]["messages"]                      # tool result was sent back with its call id
    assert second_msgs[-1]["role"] == "tool" and second_msgs[-1]["tool_call_id"] == "c1"
    blob = json.dumps(res.transcript) + json.dumps(res.report)
    assert FAKE_KEY not in blob                                     # the key never reaches logs or reports


def test_retries_on_503_then_succeeds(server):
    srv = server([(503, {}), tool_call_reply("get_binary_info", {})])
    out = OpenAIChat(base_url=srv.url, api_key="k", model="m", max_retries=2).chat([{"role": "user", "content": "x"}], [])
    assert out["tool_calls"][0]["name"] == "get_binary_info" and len(srv.requests) == 2


def test_http_error_does_not_leak_key(server):
    srv = server([(401, {"error": "bad key " + FAKE_KEY})])
    with pytest.raises(LLMError) as ei:
        OpenAIChat(base_url=srv.url, api_key=FAKE_KEY, model="m", max_retries=0).chat([], [])
    assert "SECRET" not in str(ei.value) and "401" in str(ei.value)


def test_malformed_tool_arguments_become_an_error_not_a_crash(server):
    payload = (200, {"choices": [{"message": {"content": None, "tool_calls": [
        {"id": "c", "type": "function", "function": {"name": "get_strings", "arguments": "{not json"}}]}}]})
    out = OpenAIChat(base_url=server([payload]).url, api_key="", model="m").chat([], [])
    assert out["tool_calls"][0]["arguments"] == {"_unparseable_arguments": True}


def test_no_auth_header_for_local_servers(server):
    srv = server([(200, {"choices": [{"message": {"content": "hi", "tool_calls": None}}]})])
    OpenAIChat(base_url=srv.url, api_key="", model="m").chat([], [])
    assert srv.requests[0]["auth"] is None
