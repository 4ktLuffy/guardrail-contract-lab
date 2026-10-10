"""Start Lasso's mcp-gateway with one change: the Lasso guardrail plugin's API URL.

mcp-gateway's plugin manager loads every plugin with an empty config, so the plugin's
`api_base` option cannot be set from outside; this launcher sets its default from the
GCL_LASSO_URL environment variable and then runs the gateway's own entry point with the
given arguments. Nothing else is touched.
"""
import os
import sys

import mcp_gateway.plugins.guardrails.lasso as lasso

_init = lasso.LassoGuardrailPlugin.__init__


def _init_with_url(self, *a, **kw):
    _init(self, *a, **kw)
    self.api_base = os.environ["GCL_LASSO_URL"]


lasso.LassoGuardrailPlugin.__init__ = _init_with_url

from mcp_gateway.gateway import main  # noqa: E402

sys.argv = ["mcp-gateway", *sys.argv[1:]]
main()
