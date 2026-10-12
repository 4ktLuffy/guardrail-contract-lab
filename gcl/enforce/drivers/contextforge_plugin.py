"""gcl's guard plugin for IBM ContextForge: loaded by ContextForge's own plugin framework.

ContextForge 1.0.11 ships the plugin framework (`cpex`) but no plugin that asks an HTTP
scanner for a verdict: its OPA client (cpex/framework/pdp/opa.py) is not wired into any hook,
and the eight catalogue plugins (`pip install mcp-contextforge-gateway[plugins]`) are local
detectors. So, as with Pydantic AI, gcl supplies the strictest reasonable guard and the run
tests what the *framework* does with it: the gateway's plugin executor, its modes, `on_error`
and `plugin_timeout`, and which MCP messages it hands to hooks at all.

The guard POSTs every string of the hook payload to the stand-in (pre hooks to the input
listener, post hooks to the output one), allows only on {"verdict": "ALLOW"}, blocks with
a PluginViolation on {"verdict": "BLOCK"}, and raises on anything else. Its own HTTP timeout
is longer than any gateway timeout, so a hung scanner is ended by the gateway, not by this file.

Config (plugin `config:`): input_url, output_url.
"""
import json
import urllib.request

from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
    PromptPosthookResult,
    PromptPrehookResult,
    ResourcePostFetchResult,
    ResourcePreFetchResult,
    ToolPostInvokeResult,
    ToolPreInvokeResult,
)


def strings(obj, _depth: int = 0) -> list[str]:
    """Every string in a payload, whatever it is made of (models, dicts, lists, scalars)."""
    if _depth > 12:
        return []
    if isinstance(obj, str):
        return [obj]
    if hasattr(obj, "model_dump"):
        try:
            return strings(obj.model_dump(mode="json"), _depth + 1)
        except Exception:
            return strings(vars(obj), _depth + 1)
    if isinstance(obj, dict):
        return [s for k, v in obj.items() for s in strings(k, _depth + 1) + strings(v, _depth + 1)]
    if isinstance(obj, (list, tuple, set)):
        return [s for v in obj for s in strings(v, _depth + 1)]
    return []


def ask(url: str, hook: str, payload) -> dict | None:
    """Return None to allow; return a block reason string-dict otherwise; raise on junk."""
    body = {"hook": hook, "texts": strings(payload)}
    req = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        v = json.loads(r.read())
    verdict = v.get("verdict") if isinstance(v, dict) else None
    if verdict == "ALLOW":
        return None
    if verdict == "BLOCK":
        return {"reason": str(v.get("reason") or "blocked")}
    raise RuntimeError(f"unrecognised scanner verdict: {v!r}")


class GclScanPlugin(Plugin):
    def __init__(self, config: PluginConfig):
        super().__init__(config)
        self.urls = {"pre": config.config["input_url"], "post": config.config["output_url"]}

    async def _check(self, side: str, hook: str, payload, result_cls):
        import asyncio

        blocked = await asyncio.to_thread(ask, self.urls[side], hook, payload)
        if blocked is None:
            return result_cls(continue_processing=True)
        return result_cls(continue_processing=False, violation=PluginViolation(
            reason=blocked["reason"], description="GCL-BLOCKED by the stand-in", code="GCL_BLOCK"))

    async def tool_pre_invoke(self, payload, context: PluginContext) -> ToolPreInvokeResult:
        return await self._check("pre", "tool_pre_invoke", payload, ToolPreInvokeResult)

    async def tool_post_invoke(self, payload, context: PluginContext) -> ToolPostInvokeResult:
        return await self._check("post", "tool_post_invoke", payload, ToolPostInvokeResult)

    async def prompt_pre_fetch(self, payload, context: PluginContext) -> PromptPrehookResult:
        return await self._check("pre", "prompt_pre_fetch", payload, PromptPrehookResult)

    async def prompt_post_fetch(self, payload, context: PluginContext) -> PromptPosthookResult:
        return await self._check("post", "prompt_post_fetch", payload, PromptPosthookResult)

    async def resource_pre_fetch(self, payload, context: PluginContext) -> ResourcePreFetchResult:
        return await self._check("pre", "resource_pre_fetch", payload, ResourcePreFetchResult)

    async def resource_post_fetch(self, payload, context: PluginContext) -> ResourcePostFetchResult:
        return await self._check("post", "resource_post_fetch", payload, ResourcePostFetchResult)
