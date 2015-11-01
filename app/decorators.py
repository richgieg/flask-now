from functools import wraps
from flask import abort
from flask.ext.login import current_user, fresh_login_required
from .models import Permission


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)


def permission_or_404(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(404)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_or_404(f):
    return permission_or_404(Permission.ADMINISTER)(f)

def fresh_admin_or_404(f):
    return admin_or_404(fresh_login_required(f))
