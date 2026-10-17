// The Dashboard's Domain Routing card (dc-card-domainroute, Settings ->
// Features): the address list the static DNS entries feed, how many addresses
// are on it, the mangle rules that mark routing for it and whether the tables
// they mark for have an active route. Fed by `dnsrouting:state`, which the
// server's feature loop sends once a minute, cut to what this viewer may read
// (internal/server/dnsrouting_api.go).

import type { Socket } from '../socket';
import type { DomainRoutingStatus } from '../gen/payloads';
import type { PillTone } from '../palette';
import { el, esc, pill } from '../dom';

let routerId = '';
const latest: Record<string, DomainRoutingStatus> = {};

/** The card's headline: a pill and a line. */
export function domainRouteVerdict(d: DomainRoutingStatus): { word: string; tone: PillTone; text: string } {
  if (d.error) return { word: 'off', tone: 'muted', text: d.error };
  if (!d.feeding) return { word: 'not used', tone: 'muted', text: 'No static DNS entry here feeds ' + d.list + '.' };
  if (d.ok) return { word: 'routed', tone: 'ok', text: 'Traffic to ' + d.list + ' has its route.' };
  return { word: 'down', tone: 'err', text: d.why || 'Traffic to ' + d.list + ' has no way out.' };
}

function draw(d: DomainRoutingStatus): void {
  const v = domainRouteVerdict(d);
  const head = el('dc-drVerdict');
  if (head) head.innerHTML = pill(v.word, v.tone) + ' ' + esc(v.text);
  const facts = el('dc-drFacts');
  if (facts) {
    facts.innerHTML = d.feeding
      ? '<span class="mono">' + esc(d.list) + '</span> · fed by ' + d.feeding + ' DNS entries' +
        (d.withheld.includes('Address Lists') ? '' : ' · ' + d.entries + ' addresses on it')
      : '';
  }
  const rows = el('dc-drRules');
  if (rows) {
    rows.innerHTML = d.rules.map((r) =>
      '<div class="dc-dr-row"><span>' + esc(r.chain) + ' &rarr; ' + esc(r.mark || 'no mark') +
      (r.disabled ? ' ' + pill('disabled', 'muted') : '') + '</span><span class="mono">' +
      esc(r.packets || '0') + ' pkts</span></div>').join('') +
      d.routes.map((r) =>
        '<div class="dc-dr-row"><span>' + esc(r.table) + ' ' + esc(r.dst) + ' via ' + esc(r.gateway || '?') +
        '</span>' + pill(r.active ? 'active' : 'inactive', r.active ? 'ok' : 'err') + '</div>').join('') +
      (d.feeding && d.withheld.length
        ? '<div class="muted-note">Not shown: ' + esc(d.withheld.join(', ')) + ', which you may not read.</div>' : '');
  }
}

function reset(): void {
  const head = el('dc-drVerdict');
  if (head) head.textContent = 'Waiting for the router…';
  for (const id of ['dc-drFacts', 'dc-drRules']) {
    const e = el(id);
    if (e) e.innerHTML = '';
  }
}

export function initDomainRouteCard(socket: Socket): void {
  socket.on('dnsrouting:state', (d) => {
    if (d.routerId) latest[d.routerId] = d;
    if (routerId && d.routerId && d.routerId !== routerId) return;
    draw(d);
  });
  socket.on('router:switched', (d) => {
    routerId = d.activeId;
    const known = latest[routerId];
    if (known) draw(known);
    else reset();
  });
}
