from openm.api.admin import admin_bp
from openm.api.entities import entities_bp
from openm.api.transforms import transforms_bp
from openm.api.graph import graph_bp
from openm.api.investigations import investigations_bp
from openm.api.keys import keys_bp
from openm.api.auth import auth_bp

__all__ = [
    "admin_bp",
    "entities_bp",
    "transforms_bp",
    "graph_bp",
    "investigations_bp",
    "keys_bp",
    "auth_bp",
]
