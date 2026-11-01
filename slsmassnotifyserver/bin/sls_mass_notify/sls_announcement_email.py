#!/usr/bin/python3
"""Submit one frozen announcement destination to the local MTA; never retry.

The caller owns durable intent, current authorization and destination checks.
The optional cluster guard reads protected policy before MTA submission; no
destination credentials or external mail provider are used by this helper.
"""
import json
import importlib.util
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime, formataddr
from pathlib import Path

sys.dont_write_bytecode = True
_cluster_spec = importlib.util.spec_from_file_location('sls_cluster_guard', Path(__file__).resolve().with_name('sls_cluster_guard.py'))
_cluster_guard = importlib.util.module_from_spec(_cluster_spec)
_cluster_spec.loader.exec_module(_cluster_guard)
_mail_spec = importlib.util.spec_from_file_location('sls_announcement_mail_admission', Path(__file__).resolve().with_name('sls_mail_admission.py'))
_mail_admission = importlib.util.module_from_spec(_mail_spec)
_mail_spec.loader.exec_module(_mail_admission)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sls_branded_email import (LOGO_PATHS, build_announcement_html, read_logo,
                               normalized_sender_domain, valid_recipient)

MAX_INPUT = 131072
MAX_BODY = 65536
MAX_LOGO = 262144
MAX_MIME = 1048576
SENDMAIL = '/usr/sbin/sendmail'
TIMEOUT = 5.0
FIELDS = {'recipient_id', 'address', 'sender', 'title', 'message', 'is_test',
          'severity', 'message_id', 'created_at'}


class InputError(ValueError):
    pass


class EmailAuthorizationBlocked(RuntimeError):
    """Current policy refused the handoff before any MTA process started."""


def validate_authorization(payload):
    context = payload.get('authorization')
    if context is None and 'authorization' not in payload:
        return
    if (not isinstance(context, dict) or set(context) - {'recipient_id', 'target_hashes', 'expires_at',
            'schedule_deadline', 'api_credential_id', 'api_credential_revision', 'automation_context', 'weather_context'}
            or context.get('recipient_id') != payload['recipient_id']
            or not isinstance(context.get('target_hashes'), list) or not 1 <= len(context['target_hashes']) <= 3
            or any(not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{64}', value) for value in context['target_hashes'])
            or len(set(context['target_hashes'])) != len(context['target_hashes'])
            or type(context.get('expires_at')) is not int or 'schedule_deadline' not in context
            or (context['schedule_deadline'] is not None and type(context['schedule_deadline']) is not int)
            or ('api_credential_id' in context and not isinstance(context['api_credential_id'], str))
            or ('api_credential_revision' in context and (not isinstance(context['api_credential_revision'], str)
                or not re.fullmatch(r'[a-f0-9]{64}', context['api_credential_revision'])))
            or ('automation_context' in context and not isinstance(context['automation_context'], dict))
            or ('weather_context' in context and not isinstance(context['weather_context'], dict))):
        raise InputError('The email authorization context is invalid.')


def current_email_authorization(payload):
    context = payload.get('authorization')
    if context is None:
        return True  # Preserve the legacy standalone transport contract.
    now = int(time.time())
    if context['expires_at'] <= now or (context['schedule_deadline'] is not None and context['schedule_deadline'] <= now):
        return False
    try:
        if 'weather_context' in context:
            import sls_weather_channels as weather
            source = {**context['weather_context'], 'channels': {'voice_recipient_ids': [], 'sms_recipient_ids': [], 'fingerprints': {}}}
            if weather.authorize(weather.read_config(), source).get('status') != 'eligible':
                return False
        encoded = json.dumps({key: value for key, value in context.items() if key != 'weather_context'},
                             separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(encoded) > 16384:
            return False
        result = subprocess.run(['/usr/bin/php', '/usr/local/bin/sls_mass_notify/sls_mass_notify_delivery_authorization.php', '--email'],
                    input=encoded, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=1, check=False, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        if result.returncode != 0 or len(result.stdout) >= 256:
            return False
        reply = json.loads(result.stdout, object_pairs_hook=strict_object)
        checked_at = int(time.time())
        weather_expires_at = context.get('weather_context', {}).get('source_validity', {}).get('expires_at')
        return (isinstance(reply, dict) and set(reply) == {'allowed', 'valid_until'}
                and reply['allowed'] is True and type(reply['valid_until']) is int
                and checked_at < reply['valid_until'] <= context['expires_at']
                and (context['schedule_deadline'] is None or checked_at < context['schedule_deadline'])
                and ('weather_context' not in context or (
                    checked_at < context['weather_context'].get('deadline_at', 0)
                    and type(weather_expires_at) is int and checked_at < weather_expires_at)))
    except Exception:
        # This function only reads policy; no MTA process has been started.
        return False


def checked_text(value, maximum, *, single_line=False, nonempty=True):
    if not isinstance(value, str) or (nonempty and not value.strip()):
        raise InputError('Required text is missing or has the wrong type.')
    if any(ord(char) < 32 and char not in ('\n', '\r', '\t') for char in value):
        raise InputError('Text contains unsupported control characters.')
    if single_line and any(char in value for char in ('\n', '\r', '\t')):
        raise InputError('A header contains unsupported control characters.')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError as error:
        raise InputError('Text is not valid Unicode.') from error
    if size > maximum:
        raise InputError('Announcement text exceeds its size limit.')
    return value


def validate(payload):
    if not isinstance(payload, dict) or set(payload) not in (FIELDS, FIELDS | {'authorization'}):
        raise InputError('The announcement envelope has missing or unknown fields.')
    if not isinstance(payload['recipient_id'], str) or not re.fullmatch(r'email_[a-f0-9]{24}', payload['recipient_id']):
        raise InputError('The saved email recipient ID is invalid.')
    validate_authorization(payload)
    address = checked_text(payload['address'], 254, single_line=True)
    if address != address.strip() or not valid_recipient(address):
        raise InputError('The destination email address is invalid.')
    sender = payload['sender']
    if not isinstance(sender, dict) or set(sender) != {'name', 'address'}:
        raise InputError('The sender identity is invalid.')
    checked_text(sender['name'], 320, single_line=True)
    checked_text(sender['address'], 254, single_line=True)
    if sender['address'] != sender['address'].strip() or not valid_recipient(sender['address']):
        raise InputError('The sender email address is invalid.')
    checked_text(payload['title'], 1024, single_line=True)
    checked_text(payload['message'], MAX_BODY)
    if type(payload['is_test']) is not bool or payload['severity'] not in ('info', 'warning', 'critical'):
        raise InputError('Explicit test and severity metadata is invalid.')
    identity = payload['message_id']
    if not isinstance(identity, str) or len(identity) > 340:
        raise InputError('The stable Message-ID is invalid.')
    match = re.fullmatch(r'<sls-([a-f0-9]{32})-([a-f0-9]{24})@([a-z0-9.-]+)>', identity)
    if not match or match.group(2) != payload['recipient_id'][6:] or normalized_sender_domain(match.group(3)) != match.group(3):
        raise InputError('The stable Message-ID does not identify this recipient.')
    stamp = checked_text(payload['created_at'], 40, single_line=True)
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})', stamp):
        raise InputError('Publication time must contain an explicit timezone.')
    try:
        created = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        format_datetime(created)
    except (ValueError, OverflowError) as error:
        raise InputError('Publication time is invalid.') from error
    return created


def build_message(payload, *, logo_paths=LOGO_PATHS):
    created = validate(payload)
    message = EmailMessage(policy=SMTP.clone(max_line_length=998))
    message['Subject'] = ('[TEST] ' if payload['is_test'] else '') + payload['title']
    message['From'] = formataddr((payload['sender']['name'], payload['sender']['address']))
    message['To'] = payload['address']
    message['Date'] = format_datetime(created)
    message['Message-ID'] = payload['message_id']
    message['X-SLS-Is-Test'] = 'true' if payload['is_test'] else 'false'
    message['X-SLS-Severity'] = payload['severity']
    message.set_content(payload['message'], subtype='plain', charset='utf-8')
    message.add_alternative(build_announcement_html(payload['title'], payload['message'],
                            is_test=payload['is_test'], severity=payload['severity']), subtype='html', charset='utf-8')
    logo = read_logo(logo_paths, MAX_LOGO)
    if logo is not None:
        message.get_payload()[1].add_related(logo, maintype='image', subtype='png',
                    cid='<sls-mass-notify-logo>', filename='Southland-Labs.png', disposition='inline')
    wire = message.as_bytes()
    if len(wire) > MAX_MIME:
        raise InputError('Rendered email exceeds the one MiB message limit.')
    return wire


def outcome(payload, state, code, detail, retryable=False):
    return {'ok': state == 'accepted', 'state': state, 'error_code': code,
            'message': detail, 'retryable': bool(retryable),
            'recipient_id': payload['recipient_id'], 'message_id': payload['message_id']}


def submit(payload, *, sendmail=SENDMAIL, timeout=TIMEOUT, logo_paths=LOGO_PATHS):
    wire = build_message(payload, logo_paths=logo_paths)
    claim = None
    try:
        if not current_email_authorization(payload):
            raise EmailAuthorizationBlocked()
        _mail_admission.reserve('alert', 1)
        created_at = int(datetime.fromisoformat(payload['created_at'].replace('Z', '+00:00')).timestamp())
        # Policy metadata is mutable authority, outside the immutable delivery.
        cluster_payload = {key: value for key, value in payload.items() if key != 'authorization'}
        claim = _cluster_guard.begin('email', payload['recipient_id'], cluster_payload,
                                     delivery_id='email-' + __import__('hashlib').sha256(payload['message_id'].encode()).hexdigest(),
                                     created_at=created_at)
        if not current_email_authorization(payload):
            raise EmailAuthorizationBlocked()
        process = subprocess.Popen([str(sendmail), '-oi', '-f', payload['sender']['address'], '--', payload['address']],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True, close_fds=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    except EmailAuthorizationBlocked:
        if claim is not None:
            try:
                _cluster_guard.finish(claim, uncertain=False, category='submission_suppressed', timeout=1)
            except _cluster_guard.ClusterFenced:
                pass  # The consumed claim is retained; no transport was started.
        result = outcome(payload, 'rejected', 'email_authorization_changed',
                         'Current policy no longer permits this email. No MTA process was started.', False)
        result['submission_started'] = False
        return result
    except _cluster_guard.ClusterFenced:
        return outcome(payload, 'rejected', 'cluster_authority_unavailable', 'Cluster exclusive authority is unavailable; no email process was started.', False)
    except _mail_admission.MailAdmissionBlocked as error:
        result = outcome(payload, 'rejected', error.code, str(error), False)
        result['submission_started'] = False
        return result
    except OSError:
        return outcome(payload, 'rejected', 'sendmail_unavailable', 'The PBX mail submission program could not start. Check local mail service installation and permissions.', True)
    try:
        process.communicate(wire, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        return outcome(payload, 'uncertain', 'submission_unconfirmed', 'The PBX mail service did not confirm acceptance before submission stopped. Do not automatically resend.')
    if process.returncode == 0:
        try:
            _cluster_guard.finish(claim, uncertain=False, category='local_mta_accepted')
        except _cluster_guard.ClusterFenced:
            return outcome(payload, 'uncertain', 'cluster_receipt_unconfirmed', 'PBX mail acceptance was observed but the replicated receipt is uncertain. Do not resend.')
        return outcome(payload, 'accepted', '', 'Accepted by PBX mail service. This does not confirm inbox delivery or that a person read it.')
    if process.returncode < 0:
        return outcome(payload, 'uncertain', 'submission_interrupted', 'The PBX mail submission process was interrupted before acceptance could be confirmed. Do not automatically resend.')
    # One envelope per process: a nonzero local sendmail exit rejects submission.
    return outcome(payload, 'rejected', 'sendmail_temporary_failure' if process.returncode == 75 else 'sendmail_rejected',
                   'The PBX mail service rejected this submission' + (' temporarily.' if process.returncode == 75 else '.') + ' Review the PBX mail log.', process.returncode == 75)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError('The envelope contains duplicate fields.')
        result[key] = value
    return result


def main():
    try:
        if len(sys.argv) != 1:
            raise InputError('Supply one JSON envelope on standard input; command arguments are unsupported.')
        body = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(body) > MAX_INPUT:
            raise InputError('The announcement envelope exceeds its input limit.')
        payload = json.loads(body.decode('utf-8'), object_pairs_hook=strict_object,
                             parse_constant=lambda _: (_ for _ in ()).throw(InputError('Non-finite JSON values are unsupported.')))
        result = submit(payload)
    except InputError as error:
        print(json.dumps({'ok': False, 'state': 'rejected', 'error_code': 'invalid_envelope',
                          'message': str(error) + ' No email was submitted.', 'retryable': False}))
        return 2
    except (UnicodeError, ValueError, TypeError, RecursionError):
        print(json.dumps({'ok': False, 'state': 'rejected', 'error_code': 'invalid_envelope',
                          'message': 'The announcement email envelope is invalid or exceeds its limits. No email was submitted.', 'retryable': False}))
        return 2
    except Exception:
        # Never print input, addresses, message content, config or subprocess errors.
        print(json.dumps({'ok': False, 'state': 'uncertain', 'error_code': 'sender_internal_error',
                          'message': 'The email sender stopped without a confirmed result. Do not automatically resend.', 'retryable': False}))
        return 1
    print(json.dumps(result, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
