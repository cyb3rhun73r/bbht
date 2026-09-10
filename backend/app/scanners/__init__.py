from .subdomains import run as run_subdomains
from .portscan import run as run_portscan
from .headers_misconfig import run as run_headers
from .exposure import run as run_exposure
from .sqli import run as run_sqli
from .xss import run as run_xss
from .components import run as run_components
from .access_control import run as run_access_control
from .ssrf_redirect import run as run_ssrf_redirect

MODULE_REGISTRY = {
    "subdomains": run_subdomains,
    "portscan": run_portscan,
    "headers": run_headers,
    "exposure": run_exposure,
    "sqli": run_sqli,
    "xss": run_xss,
    "components": run_components,
    "access_control": run_access_control,
    "ssrf_redirect": run_ssrf_redirect,
}
