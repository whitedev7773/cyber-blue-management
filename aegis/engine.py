"""Bounded, local configuration review. Uploaded code is never executed."""
import hashlib
import io
import json
import re
import stat
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import PurePosixPath

MAX_UPLOAD = 4 * 1024 * 1024
MAX_EXPANDED = 12 * 1024 * 1024
MAX_FILE = 512 * 1024
MAX_FILES = 250
TEAMS = {
    'access': {'name': '인증·세션 팀', 'specialists': ['쿠키 정책', '세션 수명']},
    'transport': {'name': '전송·브라우저 팀', 'specialists': ['TLS 정책', '브라우저 헤더']},
    'operations': {'name': '운영 설정 팀', 'specialists': ['디버그 설정', '감사 로그']},
}
# A deliberately small, documented policy catalog. Not a source vulnerability scanner.
POLICIES = [
    ('cookie-secure', 'access', '쿠키 정책', ('session', 'cookieSecure'), True, '세션 쿠키 Secure 설정', 'HTTPS 전용 서비스에서 세션 쿠키의 Secure 속성을 활성화하세요.'),
    ('cookie-http-only', 'access', '쿠키 정책', ('session', 'cookieHttpOnly'), True, '세션 쿠키 HttpOnly 설정', '브라우저 스크립트가 세션 쿠키를 읽지 못하도록 HttpOnly를 활성화하세요.'),
    ('session-timeout', 'access', '세션 수명', ('session', 'idleTimeoutMinutes'), 30, '세션 유휴 시간 정책', '업무 요구를 확인하고 유휴 만료를 30분 이하로 설정하세요.'),
    ('tls-required', 'transport', 'TLS 정책', ('transport', 'httpsOnly'), True, 'HTTPS 전용 정책', 'TLS 종료 지점과 프록시 구성을 확인한 뒤 HTTPS 전용 정책을 적용하세요.'),
    ('nosniff', 'transport', '브라우저 헤더', ('headers', 'nosniff'), True, '콘텐츠 유형 보호 정책', '실제 응답에 X-Content-Type-Options: nosniff가 적용되도록 설정하세요.'),
    ('debug-disabled', 'operations', '디버그 설정', ('runtime', 'debug'), False, '디버그 비활성화 정책', '운영 환경에서 디버그 출력을 비활성화하고 오류 응답을 검토하세요.'),
    ('audit-enabled', 'operations', '감사 로그', ('logging', 'auditEnabled'), True, '감사 로그 활성화 정책', '민감 값은 기록하지 않으면서 필요한 보안 이벤트를 수집하도록 설정하세요.'),
]

def safe_name(name):
    if not isinstance(name, str) or len(name) > 240 or '\\' in name or ':' in name or any(ord(c) < 32 for c in name):
        raise ValueError('허용되지 않는 파일 경로입니다.')
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('상대 경로 파일만 허용됩니다.')
    return str(path)

def collect(name, data):
    name = safe_name(name)
    if len(data) > MAX_UPLOAD:
        raise ValueError('업로드는 4 MiB 이하만 허용됩니다.')
    files, skipped = {}, []
    if name.lower().endswith('.zip'):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_FILES:
                    raise ValueError('ZIP 항목 수가 250개를 초과합니다.')
                total = 0
                seen = set()
                for info in entries:
                    path = safe_name(info.filename)
                    if path in seen:
                        raise ValueError('중복 파일 경로는 허용되지 않습니다.')
                    seen.add(path)
                    if stat.S_ISLNK(info.external_attr >> 16):
                        raise ValueError('심볼릭 링크는 허용되지 않습니다.')
                    if info.is_dir():
                        continue
                    total += info.file_size
                    if total > MAX_EXPANDED or info.file_size > MAX_FILE:
                        raise ValueError('압축 해제 크기 제한을 초과했습니다.')
                    if info.flag_bits & 1:
                        raise ValueError('암호화된 ZIP은 지원하지 않습니다.')
                    with archive.open(info) as member:
                        content = member.read(MAX_FILE + 1)
                    if len(content) > MAX_FILE:
                        raise ValueError('파일 크기 제한을 초과했습니다.')
                    files[path] = content
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
            raise ValueError('읽을 수 없는 ZIP 파일입니다.') from exc
    else:
        if len(data) > MAX_FILE:
            raise ValueError('개별 파일은 512 KiB 이하만 허용됩니다.')
        files[name] = data
    configs, imports, inventory = [], [], []
    for path, content in files.items():
        inventory.append({'path': path, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
        if PurePosixPath(path).name != 'security.config.json' and not path.endswith('.sarif'):
            skipped.append({'path': path, 'reason': 'MVP 점검 대상 형식 아님 — 소스코드 자동 취약점 분석 미지원'})
            continue
        try:
            parsed = json.loads(content.decode('utf-8-sig'))
            if not isinstance(parsed, dict):
                raise ValueError()
        except (UnicodeError, ValueError, RecursionError):
            skipped.append({'path': path, 'reason': '유효한 JSON 객체가 아님'})
            continue
        if path.endswith('.sarif'):
            imports.append((path, parsed))
        else:
            configs.append((path, parsed))
    return inventory, configs, imports, skipped

def lookup(config, keys):
    value = config
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return None, False
        value = value[key]
    return value, True

def evaluate(config, policy):
    key, _, _, path, expected, _, _ = policy
    actual, present = lookup(config, path)
    if not present:
        return 'unknown'
    if key == 'session-timeout':
        if type(actual) not in (int, float):
            return 'unknown'
        return 'pass' if 0 < actual <= expected else 'fail'
    if type(actual) is not bool:
        return 'unknown'
    return 'pass' if actual is expected else 'fail'

def specialist(team, role, configs):
    checks, findings = [], []
    for path, config in configs:
        for policy in POLICIES:
            key, group, agent, pointer, expected, title, advice = policy
            if (group, agent) != (team, role):
                continue
            state = evaluate(config, policy)
            check = {'file': path, 'rule': key, 'pointer': '/' + '/'.join(pointer), 'state': state}
            checks.append(check)
            if state == 'pass':
                continue
            # Re-read immutable input against the declared rule; not an LLM review.
            verified = evaluate(config, policy) == state
            findings.append({
                'id': hashlib.sha256(f'{path}:{key}'.encode()).hexdigest()[:16],
                'title': title, 'team': team, 'agent': role, 'file': path,
                'pointer': check['pointer'], 'rule': key, 'severity': 'medium' if state == 'fail' else 'info',
                'judgment': 'policy_mismatch' if state == 'fail' else 'needs_context',
                'evidence': ('명시된 설정이 기준과 다릅니다.' if state == 'fail' else '설정이 없거나 값의 형식이 올바르지 않습니다.'),
                'condition': '이 파일이 실제 운영 설정에 반영되는지는 별도 확인이 필요합니다.',
                'recommendation': advice, 'expected': expected,
                'review': '규칙 재검증 완료' if verified else '재검증 실패',
                'review_status': 'open', 'patch_status': 'not_applied',
                'proposed_patch': {'op': 'replace', 'path': check['pointer'], 'value': expected} if state == 'fail' else None,
                'patch_note': 'JSON Patch 제안입니다. 원본 적용·빌드·서비스 동작 검증은 수행하지 않았습니다.',
            })
    return {'team': team, 'role': role, 'engine': 'local-policy-v1', 'status': 'completed', 'checks': checks, 'findings': findings}

def import_sarif(path, document):
    """Import only metadata; never copy snippets, messages or credentials into reports."""
    results = []
    if document.get('version') != '2.1.0':
        raise ValueError('SARIF 2.1.0만 지원합니다.')
    runs = document.get('runs')
    if not isinstance(runs, list) or len(runs) > 30:
        raise ValueError('SARIF runs 형식 또는 개수 제한 오류')
    for run in runs:
        if not isinstance(run, dict) or not isinstance(run.get('results', []), list):
            raise ValueError('SARIF result 형식 오류')
        for item in run.get('results', []):
            if len(results) >= 1000:
                raise ValueError('SARIF 결과는 1,000개 이하만 허용됩니다.')
            if not isinstance(item, dict):
                raise ValueError('SARIF result 형식 오류')
            rule = str(item.get('ruleId', 'external'))[:100]
            results.append({'id': hashlib.sha256(f'{path}:{len(results)}'.encode()).hexdigest()[:16],
                'title': f'외부 도구 결과 · {rule}', 'rule': rule, 'team': 'imported', 'agent': 'SARIF 가져오기',
                'file': path, 'pointer': '', 'severity': {'error':'high', 'warning':'medium'}.get(item.get('level'), 'info'),
                'judgment': 'external_unverified', 'evidence': '외부 도구 결과를 가져왔습니다. 이 앱에서 재현·검증하지 않았습니다.',
                'condition': '원본 SARIF 보고서에서 코드 위치와 도구 설명을 검토하세요.',
                'recommendation': '원본 도구의 수정 권고를 검토하고 회귀 검증을 수행하세요.',
                'review': '미검증', 'review_status': 'open', 'patch_status': 'not_applied', 'proposed_patch': None})
    return results

def run_review(name, data, on_event=lambda event: None):
    inventory, configs, imports, skipped = collect(name, data)
    reports, findings, events = [], [], []
    def emit(event):
        events.append(event)
        on_event(event)
    jobs = [(team, role) for team, spec in TEAMS.items() for role in spec['specialists']] if configs else []
    emit({'kind': 'plan', 'message': f'{len(configs)}개 설정 · {len(jobs)}개 전문 작업', 'total': len(jobs)})
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {}
        for team, role in jobs:
            emit({'kind': 'queued', 'team': team, 'role': role, 'message': f'{role} 작업 접수'})
            futures[pool.submit(specialist, team, role, configs)] = (team, role)
        for future in as_completed(futures):
            report = future.result()
            reports.append(report)
            findings.extend(report['findings'])
            emit({'kind': 'completed', 'team': report['team'], 'role': report['role'], 'message': f"{report['role']} 보고서 제출"})
    for path, doc in imports:
        try:
            imported = import_sarif(path, doc)
            if len(findings) + len(imported) > 2000:
                raise ValueError('실행 전체 결과 2,000개 제한을 초과하여 이 보고서는 가져오지 않았습니다.')
            findings.extend(imported)
        except (ValueError, TypeError) as exc:
            skipped.append({'path': path, 'reason': str(exc)})
    findings.sort(key=lambda f: (f['file'], f['rule'], f['id']))
    reports.sort(key=lambda r: (r['team'], r['role']))
    checks = [c for r in reports for c in r['checks']]
    return {'name': name, 'status': 'completed', 'mode': 'local-policy', 'llm_connected': False,
        'inventory': inventory, 'skipped': skipped, 'reports': reports, 'findings': findings, 'events': events,
        'coverage': {'files': len(inventory), 'config_files': len(configs), 'checks': len(checks),
                     'passed': sum(c['state'] == 'pass' for c in checks),
                     'unknown': sum(c['state'] == 'unknown' for c in checks)},
        'limitations': ['소스코드 취약점 자동 탐지는 제공하지 않습니다.', '7개 고정 설정 기준만 검사합니다. 실제 배포 상태는 확인하지 않습니다.',
                        '전문 작업은 로컬 규칙 작업자입니다. LLM·독립 모델 검토는 연결되지 않았습니다.',
                        '패치는 제안이며 원본 수정이나 실행 검증을 수행하지 않습니다.']}
