import json
import os
from pathlib import Path
import re
import secrets
import sys
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class Failure(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        raise Failure('redirect_refused')


def request(url, headers, data=None, method=None, limit=16384):
    try:
        with build_opener(NoRedirect).open(Request(url, headers=headers, data=data, method=method), timeout=35) as response:
            body = response.read(limit + 1)
            if len(body) > limit:
                raise Failure('response_too_large')
            return response.status, body
    except Exception:
        raise Failure('request_not_confirmed') from None


def context(env):
    expected = {
        'GITHUB_ACTIONS': 'true',
        'GITHUB_REPOSITORY': 'etamong-playground/mcp-go',
        'GITHUB_REPOSITORY_ID': '1431206777',
        'GITHUB_REPOSITORY_OWNER_ID': '295270411',
        'GITHUB_EVENT_NAME': 'workflow_dispatch',
        'GITHUB_REF': 'refs/heads/main',
    }
    if any(env.get(key) != value for key, value in expected.items()):
        raise Failure('caller_context_refused')
    if env.get('UPDATER_WRITE') not in ('true', 'false'):
        raise Failure('explicit_write_mode_required')
    origin = env.get('UPDATER_BROKER_ORIGIN', '')
    parsed = urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment
            or any(character.isspace() for character in origin) or '\\' in origin):
        raise Failure('broker_origin_not_configured')
    if env.get('UPDATER_AUDIENCE') != 'https://hoopa.onul.me/dependency-updates':
        raise Failure('audience_not_configured')
    return origin.rstrip('/')


def mint(env, send=request, emit=print):
    origin = context(env)
    output = Path(env['GITHUB_OUTPUT'])
    if not output.is_file():
        raise Failure('runtime_output_unavailable')
    level = 'write' if env['UPDATER_WRITE'] == 'true' else 'read'
    operation = {
        'operation_id': secrets.token_hex(16),
        'created_at': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
        'repositories': ['mcp-go'],
        'permissions': {'contents': level, 'pull_requests': level, 'statuses': level, 'issues': 'read'},
    }
    record = Path(env['GITHUB_WORKSPACE']) / '.tmp/dependency-updates-operation.json'
    record.parent.mkdir(parents=True, exist_ok=True)
    try:
        with record.open('x', encoding='utf-8') as stream:
            json.dump(operation, stream)
    except FileExistsError:
        raise Failure('existing_operation_requires_review') from None
    oidc_url = urlsplit(env.get('ACTIONS_ID_TOKEN_REQUEST_URL', ''))
    if (oidc_url.scheme != 'https' or not oidc_url.hostname
            or not oidc_url.hostname.endswith('.actions.githubusercontent.com')
            or oidc_url.username or oidc_url.password or oidc_url.fragment):
        raise Failure('oidc_endpoint_refused')
    query = [(key, value) for key, value in parse_qsl(oidc_url.query) if key != 'audience']
    query.append(('audience', env['UPDATER_AUDIENCE']))
    url = urlunsplit(oidc_url._replace(query=urlencode(query)))
    request_token = env.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '')
    if not request_token or any(character.isspace() for character in request_token):
        raise Failure('oidc_request_credential_unavailable')
    status, body = send(url, {'Authorization': 'Bearer ' + request_token})
    try:
        assertion = json.loads(body)['value']
        if status != 200 or not isinstance(assertion, str) or not assertion or len(assertion) > 16384 or any(character.isspace() for character in assertion):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise Failure('oidc_response_refused') from None
    status, body = send(origin + '/mint/ditto-github-token',
                        {'Authorization': 'Bearer ' + assertion, 'Content-Type': 'application/json'},
                        json.dumps(operation).encode())
    if status != 201:
        raise Failure('issuance_not_confirmed_inspect_operation')
    try:
        token = body.decode('ascii').removesuffix('\n')
        if not re.fullmatch(r'[A-Za-z0-9_]{32,4096}', token):
            raise ValueError()
    except (UnicodeError, ValueError):
        raise Failure('provider_credential_response_refused') from None
    try:
        emit('::add-mask::' + token)
        with output.open('a', encoding='utf-8') as stream:
            stream.write('token=' + token + '\n')
    except Exception:
        revoke({'UPDATER_TOKEN': token}, send)
        raise Failure('runtime_output_failed') from None


def revoke(env, send=request):
    token = env.get('UPDATER_TOKEN', '')
    if not token:
        raise Failure('cleanup_credential_unavailable')
    status, _ = send('https://api.github.com/installation/token',
                     {'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'},
                     method='DELETE')
    if status != 204:
        raise Failure('credential_revocation_not_confirmed')


def main():
    try:
        if sys.argv[1:] == ['mint']:
            mint(os.environ)
        elif sys.argv[1:] == ['revoke']:
            revoke(os.environ)
        else:
            raise Failure('unsupported_operation')
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, Failure) else 'caller_operation_failed'
        print('Dependency updater stopped: ' + code, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
