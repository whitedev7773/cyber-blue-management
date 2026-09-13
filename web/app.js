'use strict';
const $ = id => document.getElementById(id);
const teams = {access: ['인증·세션 팀', '쿠키 정책 · 세션 수명', '◇'], transport: ['전송·브라우저 팀', 'TLS 정책 · 브라우저 헤더', '⇄'], operations: ['운영 설정 팀', '디버그 설정 · 감사 로그', '⚙']};
const labels = {policy_mismatch: '설정 편차', needs_context: '확인 필요', external_unverified: '외부 미검증', open: '미검토', accepted: '수용', dismissed: '기각', deferred: '보류', completed: '완료', running: '분석 중', queued: '대기 중', failed: '실패'};
let token = '', active = null, current = null, timer = null, generation = 0, uploading = false;
function el(tag, text, className) {const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node;}
function error(message = '') {$('error').textContent = message; $('error').hidden = !message;}
async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {...options.headers, 'X-Aegis-Token': token}});
  const data = await response.json(); if (!response.ok) throw new Error(data.error || '요청에 실패했습니다.'); return data;
}
function download(name, data, mime = 'application/json') {
  const url = URL.createObjectURL(new Blob([typeof data === 'string' ? data : JSON.stringify(data, null, 2)], {type: mime}));
  const link = el('a'); link.href = url; link.download = name; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function history() {
  const runs = await api('/api/runs'); $('history').replaceChildren();
  if (!runs.length) $('history').append(el('p', '아직 분석이 없습니다.', 'muted'));
  for (const run of runs) {
    const button = el('button', run.name, run.id === active ? 'selected' : '');
    button.append(el('small', `${labels[run.status] || run.status} · ${new Date(run.created * 1000).toLocaleString('ko-KR')}`));
    button.addEventListener('click', () => select(run.id).catch(e => error(e.message))); $('history').append(button);
  }
}
async function select(id) {
  const ticket = ++generation; active = id; clearTimeout(timer); error(); $('detail').close();
  const data = await api(`/api/runs/${id}`); if (ticket !== generation) return;
  current = data; render(); await history();
  if (['running', 'queued'].includes(data.status)) timer = setTimeout(() => {if (ticket === generation) select(id).catch(e => error(e.message));}, 700);
}
function renderTeams() {
  $('teams').replaceChildren();
  for (const [key, [name, roles, icon]] of Object.entries(teams)) {
    const row = el('div', undefined, 'team'); row.append(el('span', icon, 'team-icon'));
    const text = el('div'); text.append(el('div', name, 'team-name'), el('div', roles, 'team-meta')); row.append(text);
    const count = (current?.reports || []).filter(r => r.team === key).length;
    row.append(el('span', current?.status === 'completed' ? (count ? `${count}/2 완료` : '대상 없음') : current?.status === 'failed' ? '중단' : current ? '대기·처리 중' : '대기', 'team-status')); $('teams').append(row);
  }
}
function render() {
  renderTeams(); const c = current?.coverage; const findings = current?.findings || [];
  $('findingCount').textContent = c ? findings.length : '—'; $('passedCount').textContent = c ? `${c.passed} / ${c.checks}` : '—';
  $('taskCount').textContent = current?.reports ? current.reports.length : '—'; $('skippedCount').textContent = current?.skipped ? current.skipped.length : '—';
  $('runName').textContent = current?.name || '분석을 시작하면 기록이 표시됩니다.'; $('runStatus').textContent = labels[current?.status] || '대기';
  $('events').replaceChildren(); for (const event of current?.events || []) $('events').append(el('li', event.message));
  if (!$('events').children.length) $('events').append(el('li', '파일을 선택하거나 예제를 실행하세요.', 'muted'));
  if (current?.status === 'failed') error(current.error);
  $('export').disabled = current?.status !== 'completed'; $('delete').disabled = !current || ['running', 'queued'].includes(current.status);
  $('coverage').replaceChildren();
  for (const limitation of current?.limitations || []) $('coverage').append(el('p', limitation));
  const list = el('ul');
  for (const file of current?.inventory || []) {
    const skip = current.skipped.find(s => s.path === file.path);
    const checked = current.reports.some(r => r.checks.some(c => c.file === file.path));
    list.append(el('li', `${file.path} · ${file.bytes} bytes — ${skip ? skip.reason : checked ? '설정 기준 점검' : '외부 보고서 가져오기 (미검증)'}`));
  }
  $('coverage').append(list); renderFindings();
}
function renderFindings() {
  const all = current?.findings || []; $('resultBadge').textContent = all.length;
  const filtered = all.filter(f => $('filter').value === 'all' || f.judgment === $('filter').value);
  $('findings').replaceChildren();
  for (const f of filtered) {
    const row = el('tr'), severity = el('td'); severity.append(el('span', f.severity.toUpperCase(), `severity ${f.severity}`)); row.append(severity);
    const name = el('td'), button = el('button', f.title, 'finding-link'); button.addEventListener('click', () => detail(f));
    name.append(button, el('small', `${f.file}${f.pointer ? ' #' + f.pointer : ''}`)); row.append(name);
    row.append(el('td', teams[f.team]?.[0] || '외부 보고서'), el('td', labels[f.judgment]), el('td', labels[f.review_status])); $('findings').append(row);
  }
  if (!filtered.length) {const row = el('tr'), cell = el('td', current?.status === 'completed' ? '이 범위에서 표시할 발견 사항이 없습니다. 미검토 범위도 확인하세요.' : '분석 결과가 여기에 표시됩니다.', 'empty'); cell.colSpan = 5; row.append(cell); $('findings').append(row);}
}
function detail(f) {
  const box = $('detailContent'); box.replaceChildren(el('h2', f.title, 'detail-title'), el('p', `${f.file} ${f.pointer || ''}`));
  const field = (title, content) => {const group = el('section', undefined, 'detail-field'); group.append(el('h3', title), el('p', content)); box.append(group);};
  field('판정 · 검토', `${labels[f.judgment]} / ${f.review} / ${labels[f.review_status]}`);
  field('코드·설정 근거', f.evidence); field('발생 조건과 한계', f.condition); field('권장 수정', f.recommendation);
  field('수정 검증 상태', f.patch_note || '패치 적용 및 실행 검증을 수행하지 않았습니다.');
  if (f.proposed_patch) {box.append(el('pre', JSON.stringify([f.proposed_patch], null, 2))); const button = el('button', '제안 JSON Patch 다운로드', 'button secondary compact'); button.addEventListener('click', () => download(`aegis-${f.id}.patch.json`, [f.proposed_patch])); box.append(button);}
  const actions = el('div', undefined, 'detail-actions');
  for (const state of ['accepted', 'deferred', 'dismissed', 'open']) {
    const button = el('button', labels[state], 'button secondary compact'); button.disabled = f.review_status === state;
    button.addEventListener('click', async () => {
      const id = active; actions.querySelectorAll('button').forEach(b => b.disabled = true);
      try {const result = await api(`/api/runs/${id}/review`, {method: 'POST', body: JSON.stringify({finding_id: f.id, state})}); if (id !== active) return; current = result; render(); detail(current.findings.find(x => x.id === f.id));}
      catch(e) {error(e.message); $('detail').close();}
    }); actions.append(button);
  }
  box.append(actions); if (!$('detail').open) $('detail').showModal();
}
async function upload(name, data) {
  if (uploading) return;
  if (data.size > 4 * 1024 * 1024) return error('업로드는 4 MiB 이하만 허용됩니다.');
  uploading = true; $('demo').disabled = true; $('file').disabled = true; error();
  try {const result = await api(`/api/runs?name=${encodeURIComponent(name)}`, {method: 'POST', headers: {'Content-Type': 'application/octet-stream'}, body: data}); await select(result.id);}
  catch(e) {error(e.message);} finally {uploading = false; $('demo').disabled = false; $('file').disabled = false; $('file').value = '';}
}
$('file').addEventListener('change', () => {const file = $('file').files[0]; if(file) upload(file.name, file);});
$('demo').addEventListener('click', () => upload('security.config.json', new Blob([JSON.stringify({session:{cookieSecure:false,cookieHttpOnly:true,idleTimeoutMinutes:120},transport:{httpsOnly:true},headers:{nosniff:false},runtime:{debug:true},logging:{auditEnabled:true}}, null, 2)])));
$('filter').addEventListener('change', renderFindings);
$('refresh').addEventListener('click', () => history().catch(e => error(e.message)));
$('closeDetail').addEventListener('click', () => $('detail').close());
$('export').addEventListener('click', () => {if(current) download(`aegis-report-${current.id}.json`, current);});
$('delete').addEventListener('click', async () => {
  if (!current || !confirm('이 분석 결과와 검토 이력을 삭제할까요?')) return;
  const id = active;
  try {await api(`/api/runs/${id}`, {method: 'DELETE'}); if (active === id) {clearTimeout(timer); generation++; active = null; current = null; render();} await history();} catch(e) {error(e.message);}
});
$('newNav').addEventListener('click', () => $('file').click());
$('overviewNav').addEventListener('click', () => window.scrollTo({top: 0, behavior: 'smooth'}));
(async () => {render(); try {token = (await api('/api/session')).token; await history();} catch(e) {error(e.message);}})();
