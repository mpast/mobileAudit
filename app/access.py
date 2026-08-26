import secrets


GUEST_SCAN_CAPABILITIES_SESSION_KEY = 'guest_scan_capabilities'
GUEST_APP_CAPABILITIES_SESSION_KEY = 'guest_app_capabilities'


def grant_guest_scan_access(request, scan):
    """Grant this browser an unguessable, session-bound capability for a scan."""
    capabilities = request.session.get(GUEST_SCAN_CAPABILITIES_SESSION_KEY, {})
    capabilities[str(scan.pk)] = secrets.token_urlsafe(32)
    request.session[GUEST_SCAN_CAPABILITIES_SESSION_KEY] = capabilities
    request.session.modified = True


def grant_guest_app_access(request, app):
    """Grant this browser an unguessable, session-bound capability for an app."""
    capabilities = request.session.get(GUEST_APP_CAPABILITIES_SESSION_KEY, {})
    capabilities[str(app.pk)] = secrets.token_urlsafe(32)
    request.session[GUEST_APP_CAPABILITIES_SESSION_KEY] = capabilities
    request.session.modified = True


def guest_scan_ids(request):
    capabilities = request.session.get(GUEST_SCAN_CAPABILITIES_SESSION_KEY, {})
    if not isinstance(capabilities, dict):
        return []

    return [int(scan_id) for scan_id in capabilities if scan_id.isdigit()]


def guest_app_ids(request):
    capabilities = request.session.get(GUEST_APP_CAPABILITIES_SESSION_KEY, {})
    if not isinstance(capabilities, dict):
        return []

    return [int(app_id) for app_id in capabilities if app_id.isdigit()]


def can_access_app(request, app):
    if app.user_id is not None:
        return request.user.is_authenticated and app.user_id == request.user.id

    capabilities = request.session.get(GUEST_APP_CAPABILITIES_SESSION_KEY, {})
    if not isinstance(capabilities, dict):
        return False

    capability = capabilities.get(str(app.pk))
    return isinstance(capability, str) and bool(capability)


def can_access_scan(request, scan):
    if scan.user_id is not None:
        return request.user.is_authenticated and scan.user_id == request.user.id

    capabilities = request.session.get(GUEST_SCAN_CAPABILITIES_SESSION_KEY, {})
    if not isinstance(capabilities, dict):
        return False

    capability = capabilities.get(str(scan.pk))
    return isinstance(capability, str) and bool(capability)
