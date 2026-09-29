import hashlib
import secrets

from django.conf import settings


GUEST_SCAN_CAPABILITIES_SESSION_KEY = 'guest_scan_capabilities'
GUEST_APP_CAPABILITIES_SESSION_KEY = 'guest_app_capabilities'
GUEST_SESSION_HANDSHAKE_MESSAGE = 'Guest session established. Retry the request with the session cookie.'


def _session_fingerprint(session_key):
    return hashlib.sha256(session_key.encode('utf-8')).hexdigest()


def has_established_guest_session(request):
    cookie_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
    return bool(cookie_key and request.session.exists(cookie_key))


def ensure_guest_session(request):
    if not has_established_guest_session(request):
        request.session.create()


def grant_guest_scan_access(request, scan):
    """Grant this browser an unguessable, session-bound capability for a scan."""
    if request.session.session_key is None:
        request.session.create()

    fingerprint = _session_fingerprint(request.session.session_key)
    if scan.guest_session_fingerprint != fingerprint:
        scan.guest_session_fingerprint = fingerprint
        scan.save(update_fields=['guest_session_fingerprint'])

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
    capability_ids = []
    if isinstance(capabilities, dict):
        capability_ids = [int(scan_id) for scan_id in capabilities if scan_id.isdigit()]

    session_key = request.session.session_key
    if not session_key:
        return capability_ids

    from app.models import Scan

    fingerprint = _session_fingerprint(session_key)
    if capability_ids:
        Scan.objects.filter(
            pk__in=capability_ids,
            user__isnull=True,
        ).exclude(guest_session_fingerprint=fingerprint).update(
            guest_session_fingerprint=fingerprint,
        )
    durable_ids = Scan.objects.filter(
        user__isnull=True,
        guest_session_fingerprint=fingerprint,
    ).values_list('pk', flat=True)
    return list(set(capability_ids).union(durable_ids))


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

    session_key = request.session.session_key
    if scan.guest_session_fingerprint and session_key:
        if secrets.compare_digest(scan.guest_session_fingerprint, _session_fingerprint(session_key)):
            return True

    capabilities = request.session.get(GUEST_SCAN_CAPABILITIES_SESSION_KEY, {})
    if not isinstance(capabilities, dict):
        return False

    capability = capabilities.get(str(scan.pk))
    has_capability = isinstance(capability, str) and bool(capability)
    if has_capability and session_key:
        fingerprint = _session_fingerprint(session_key)
        if scan.guest_session_fingerprint != fingerprint:
            scan.guest_session_fingerprint = fingerprint
            scan.save(update_fields=['guest_session_fingerprint'])
    return has_capability
