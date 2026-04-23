"""Import-time Vercel shim for this mixed Python/Next.js repository.

The real demo app lives in demo-app/. This root entrypoint exists only so
Vercel's Python auto-detection does not fail before monorepo settings can be
applied.
"""


def app(environ, start_response):
    body = (
        b"Beaconing Detection System repository root. "
        b"Deploy the Next.js demo from demo-app/ on the operational-system branch."
    )
    headers = [
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ]
    start_response("200 OK", headers)
    return [body]
