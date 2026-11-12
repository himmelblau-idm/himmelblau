'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { run, evaluate, ciReasons, REQUIRED_CI } = require('./review-policy.js');

const SHA = 'a'.repeat(40);
const OLD = 'b'.repeat(40);
const user = login => ({ login, type: 'User' });
const bot = login => ({ login, type: 'Bot' });
const pr = () => ({ number: 1, state: 'open', draft: false, user: user('author'),
  head: { sha: SHA }, base: { ref: 'main', sha: OLD }, mergeable: true, mergeable_state: 'clean' });
const review = (login = 'maintainer', extra = {}) => ({ id: 1, user: user(login), state: 'APPROVED', commit_id: SHA, body: '', ...extra });
const check = (name, extra = {}) => ({ id: 1, name, app: { id: 15368 }, status: 'completed', conclusion: 'success', ...extra });
const snapshot = () => ({ pr: pr(), authorCanWrite: true, permissions: { maintainer: true },
  reviews: [review()], threads: [], checks: [], comments: [] });
const coderabbitCheck = () => check('CodeRabbit', { app: { id: 347564, slug: 'coderabbitai' } });
const coderabbitReview = () => review('coderabbitai[bot]', { user: bot('coderabbitai[bot]'), state: 'COMMENTED' });
const coderabbitSummary = () => ({ id: 1, user: bot('coderabbitai[bot]'), body:
  `<!-- change_assessment_commit:"${SHA}" -->\n<!-- recent_review_status_start -->\nNo actionable comments were generated in the recent review.\n<!-- recent_review_status_end -->` });

test('write-access author can merge with one human approval', () => {
  assert.equal(evaluate(snapshot()).eligible, true);
});
test('external author needs two distinct reviewers, at least one human', () => {
  const s = { ...snapshot(), authorCanWrite: false };
  assert.equal(evaluate(s).eligible, false);
  s.reviews.push(review('other', { id: 2 })); s.permissions.other = true;
  assert.equal(evaluate(s).eligible, true);
  s.reviews[1] = review('maintainer', { id: 2 });
  assert.equal(evaluate(s).eligible, false);
});
test('current clean CodeRabbit review qualifies without an approval checkmark', () => {
  const s = { ...snapshot(), reviews: [coderabbitReview()], checks: [coderabbitCheck()], comments: [coderabbitSummary()] };
  assert.equal(evaluate(s).eligible, true);
  s.authorCanWrite = false;
  assert.equal(evaluate(s).eligible, false);
  s.reviews.push(review('maintainer', { id: 2 }));
  assert.equal(evaluate(s).eligible, true);
});
test('two AI providers cannot satisfy the external human requirement', () => {
  const s = { ...snapshot(), authorCanWrite: false, reviews: [
    review('maintainer', { body: '<!-- review-policy:ai:codex -->' }),
    review('other', { id: 2, body: '<!-- review-policy:ai:copilot -->' }),
  ], permissions: { maintainer: true, other: true } };
  assert.equal(evaluate(s).eligible, false);
});
test('delegated AI approvals never count as human, including historical Codex disclosure', () => {
  for (const body of ['<!-- review-policy:ai:codex -->', 'I’m contributing this review as Codex at exact head']) {
    const s = { ...snapshot(), authorCanWrite: false,
      reviews: [review('maintainer', { body }), review('other', { id: 2, body: '<!-- review-policy:ai:copilot -->' })],
      permissions: { maintainer: true, other: true } };
    assert.equal(evaluate(s).eligible, false);
    assert.ok(evaluate(s).reviewers.includes('ai:codex'));
  }
});
test('one provider cannot count twice across bot and delegated reviews', () => {
  const s = { ...snapshot(), authorCanWrite: false, reviews: [review('maintainer'),
    review('other', { id: 2, body: '<!-- review-policy:ai:codex -->' }),
    review('chatgpt-codex-connector[bot]', { id: 3, user: bot('chatgpt-codex-connector[bot]') })],
  permissions: { maintainer: true, other: true } };
  assert.deepEqual(evaluate(s).reviewers.sort(), ['ai:codex', 'human:maintainer']);
});
test('self reviews, read-only reviewers and untrusted bots never count', () => {
  for (const r of [review('author'), review('stranger'), review('untrusted[bot]', { user: bot('untrusted[bot]') })]) {
    assert.equal(evaluate({ ...snapshot(), permissions: { author: true }, reviews: [r] }).eligible, false);
  }
});
test('spoofing a bot login with a User account does not count', () => {
  const s = { ...snapshot(), reviews: [{ ...coderabbitReview(), user: user('coderabbitai[bot]') }],
    checks: [coderabbitCheck()], comments: [coderabbitSummary()] };
  assert.equal(evaluate(s).eligible, false);
});
test('reviews on earlier heads and dismissed approvals cannot qualify', () => {
  const s = snapshot();
  s.reviews[0].commit_id = OLD;
  assert.equal(evaluate(s).eligible, false);
  s.reviews = [review(), review('maintainer', { id: 2, state: 'DISMISSED' })];
  assert.equal(evaluate(s).eligible, false);
});
test('comments and pending reviews do not erase changes requests or approvals', () => {
  const s = snapshot();
  s.reviews.push(review('maintainer', { id: 2, state: 'COMMENTED' }));
  assert.equal(evaluate(s).eligible, true);
  s.reviews[0].state = 'CHANGES_REQUESTED';
  s.reviews.push(review('other', { id: 3 })); s.permissions.other = true;
  assert.equal(evaluate(s).eligible, false);
  s.reviews.push(review('maintainer', { id: 4, state: 'PENDING' }));
  assert.equal(evaluate(s).eligible, false);
  s.reviews.push(review('maintainer', { id: 5, state: 'DISMISSED' }));
  assert.equal(evaluate(s).eligible, true);
});
test('unresolved outdated threads, drafts, closed PRs and other bases block', () => {
  const s = snapshot();
  s.threads.push({ isResolved: false, isOutdated: true });
  assert.equal(evaluate(s).eligible, false);
  s.threads[0].isResolved = true;
  assert.equal(evaluate(s).eligible, true);
  for (const patch of [{ draft: true }, { state: 'closed' }, { base: { ref: 'stable-4.x' } }]) {
    assert.equal(evaluate({ ...snapshot(), pr: { ...pr(), ...patch } }).eligible, false);
  }
});
test('CodeRabbit completion alone, wrong app, stale summary and findings fail closed', () => {
  const s = { ...snapshot(), reviews: [coderabbitReview()], checks: [coderabbitCheck()], comments: [] };
  assert.equal(evaluate(s).eligible, false);
  s.comments = [coderabbitSummary()]; s.checks[0].app.id = 1;
  assert.equal(evaluate(s).eligible, false);
  s.checks = [coderabbitCheck()]; s.comments[0].body = s.comments[0].body.replace(SHA, OLD);
  assert.equal(evaluate(s).eligible, false);
  s.comments = [coderabbitSummary()]; s.reviews[0].body = '**Actionable comments posted: 1**';
  assert.equal(evaluate(s).eligible, false);
  s.reviews[0].body = 'Failed pre-merge checks:';
  assert.equal(evaluate(s).eligible, false);
});
test('later non-clean bot review or summary supersedes a clean one on the same head', () => {
  const s = { ...snapshot(), reviews: [coderabbitReview(), { ...coderabbitReview(), id: 2, body: '**Actionable comments posted: 1**' }],
    checks: [coderabbitCheck()], comments: [coderabbitSummary()] };
  assert.equal(evaluate(s).eligible, false);
  s.reviews.pop(); s.comments.push({ ...coderabbitSummary(), id: 2, body: '<!-- recent_review_status_start -->Review in progress<!-- recent_review_status_end -->' });
  assert.equal(evaluate(s).eligible, false);
});
test('Copilot needs Ready to approve, not merely No open issues', () => {
  const s = { ...snapshot(), reviews: [review('copilot-pull-request-reviewer[bot]', {
    user: bot('copilot-pull-request-reviewer[bot]'), state: 'COMMENTED',
    body: '<!-- ccr-overview-v2 -->\n\n### 🔵 Needs a closer look\n\n**No open issues** 🎉' })] };
  assert.equal(evaluate(s).eligible, false);
  s.reviews[0].body = s.reviews[0].body.replace('🔵 Needs a closer look', '🟢 Ready to approve');
  assert.equal(evaluate(s).eligible, true);
});
test('Codex clean formal review is accepted, prose mentions and reactions are not', () => {
  const s = { ...snapshot(), reviews: [review('chatgpt-codex-connector[bot]', {
    user: bot('chatgpt-codex-connector[bot]'), state: 'COMMENTED',
    body: "### Codex Review: Didn't find any major issues." })] };
  assert.equal(evaluate(s).eligible, true);
  s.reviews[0].body = 'Consider this text: No findings.';
  assert.equal(evaluate(s).eligible, false);
  s.reviews = []; s.comments = [{ user: bot('chatgpt-codex-connector[bot]'), body: '👍' }];
  assert.equal(evaluate(s).eligible, false);
});
test('mandatory CI must exist and succeed from the Actions app', () => {
  const checks = REQUIRED_CI.map(name => check(name));
  assert.deepEqual(ciReasons(checks, []), []);
  for (const state of ['failure', 'cancelled', 'skipped', 'neutral']) {
    assert.notEqual(ciReasons([{ ...checks[0], conclusion: state }, ...checks.slice(1)], []).length, 0);
  }
  assert.notEqual(ciReasons(checks.slice(1), []).length, 0);
  assert.notEqual(ciReasons([{ ...checks[0], app: { id: 1 } }, ...checks.slice(1)], []).length, 0);
});
test('Codex top-level clean comments must identify current reviewed commit', () => {
  const s = { ...snapshot(), reviews: [], comments: [{ id: 1,
    user: bot('chatgpt-codex-connector[bot]'), created_at: '2026-11-12T10:00:00Z',
    body: `Codex Review: Didn't find any major issues. Nice work! Reviewed commit: \`${SHA.slice(0, 10)}\`` }] };
  assert.equal(evaluate(s).eligible, true);
  s.comments[0].body = s.comments[0].body.replace(SHA.slice(0, 10), OLD.slice(0, 10));
  assert.equal(evaluate(s).eligible, false);
  s.comments[0].body = `Codex Review: Didn't find any major issues. Reviewed commit: \`${SHA}\``;
  s.reviews.push(review('chatgpt-codex-connector[bot]', { user: bot('chatgpt-codex-connector[bot]'),
    state: 'COMMENTED', submitted_at: '2026-11-12T11:00:00Z', body: 'Found a problem.' }));
  assert.equal(evaluate(s).eligible, false);
  s.reviews = []; s.comments[0].user.type = 'User';
  assert.equal(evaluate(s).eligible, false);
});
test('latest CI rerun wins; running policy jobs do not block themselves', () => {
  const checks = REQUIRED_CI.map(name => check(name));
  assert.notEqual(ciReasons([...checks, check('Build', { id: 2, status: 'queued', conclusion: null })], []).length, 0);
  assert.deepEqual(ciReasons([...checks, check('Evaluate main reviews', { status: 'in_progress', conclusion: null }),
    check('Review policy', { conclusion: 'failure' }), check('Review policy wakeup', { conclusion: 'failure' })], []), []);
  assert.notEqual(ciReasons([...checks, check('other', { conclusion: 'failure' })], []).length, 0);
  assert.notEqual(ciReasons(checks, [{ id: 1, context: 'external CI', state: 'pending' }]).length, 0);
});

// API mocks exercise the side effects and boundaries, not just the vote count.
function harness({ changeHead = false, changeBase = false, mergeState = 'clean', permissionError = false,
  unresolved = false, ciFailure = false, syntheticCI = false, latestRabbitPending = false } = {}) {
  const calls = [];
  const initial = pr();
  initial.mergeable_state = mergeState;
  if (syntheticCI) initial.merge_commit_sha = 'c'.repeat(40);
  let reads = 0;
  const github = {
    rest: {
      pulls: {
        list: async () => [initial],
        get: async () => ({ data: { ...initial, head: { sha: changeHead && ++reads > 1 ? OLD : SHA },
          base: { ...initial.base, ref: changeBase && ++reads > 1 ? 'stable-4.x' : 'main' } } }),
        listReviews: async () => latestRabbitPending ? [coderabbitReview()] : [review()],
        merge: async args => { calls.push(['merge', args]); return { data: { merged: true, message: 'merged' } }; },
      },
      repos: {
        getCollaboratorPermissionLevel: async () => {
          if (permissionError) throw Object.assign(new Error('forbidden'), { status: 403 });
          return { data: { permission: 'write' } };
        },
        listCommitStatusesForRef: async () => [],
      },
      issues: { listComments: async () => latestRabbitPending ? [coderabbitSummary()] : [] },
      checks: {
        listForRef: async args => syntheticCI && args.ref === SHA ? []
          : [...REQUIRED_CI.map(name => check(name, { conclusion: ciFailure && name === 'Build' ? 'failure' : 'success' })),
            ...(latestRabbitPending ? [coderabbitCheck(), { ...coderabbitCheck(), id: 2, status: 'in_progress', conclusion: null }] : [])],
        create: async args => { calls.push(['check', args]); return { data: { id: 99 } }; },
        update: async args => { calls.push(['update', args]); },
      },
    },
    paginate: async (method, args) => method(args),
    graphql: async (_query, args) => {
      calls.push(['threads', args.cursor]);
      return { repository: { pullRequest: { reviewThreads: {
        nodes: [{ isResolved: !unresolved || args.cursor === null }],
        pageInfo: { hasNextPage: args.cursor === null, endCursor: 'page2' },
      } } } };
    },
  };
  const core = { info: () => {}, error: () => {}, setFailed: value => calls.push(['error', value]) };
  return { github, core, context: { repo: { owner: 'himmelblau-idm', repo: 'himmelblau' } }, calls };
}
test('coordinator merges with expected SHA and squash only after reloading PR', async () => {
  const h = harness(); await run({ ...h, merge: true });
  assert.equal(h.calls.filter(c => c[0] === 'threads').length, 2);
  const merge = h.calls.find(c => c[0] === 'merge')[1];
  assert.equal(merge.sha, SHA); assert.equal(merge.merge_method, 'squash');
});
test('coordinator report-only mode never merges', async () => {
  const h = harness(); await run(h);
  assert.equal(h.calls.some(c => c[0] === 'merge'), false);
  assert.equal(h.calls.find(c => c[0] === 'check')[1].conclusion, 'success');
});
test('race, blocked state, failed CI, permission errors and paginated unresolved threads prevent merge', async () => {
  for (const options of [{ changeHead: true }, { changeBase: true }, { mergeState: 'behind' },
    { mergeState: 'blocked' }, { permissionError: true }, { unresolved: true }, { ciFailure: true }, { latestRabbitPending: true }]) {
    const h = harness(options); await run({ ...h, merge: true });
    assert.equal(h.calls.some(c => c[0] === 'merge'), false, JSON.stringify(options));
  }
});
test('CI attached to the current synthetic merge satisfies mandatory jobs', async () => {
  const h = harness({ syntheticCI: true }); await run({ ...h, merge: true });
  assert.equal(h.calls.some(c => c[0] === 'merge'), true);
});
test('coordinator rejects stable PRs even if API list unexpectedly returns one', async () => {
  const h = harness(); h.github.rest.pulls.get = async () => ({ data: { ...pr(), base: { ref: 'stable-4.x' } } });
  await run({ ...h, merge: true });
  assert.deepEqual(h.calls, []);
});
test('workflow uses main checkout and no untrusted code or credentials persistence', () => {
  const workflow = fs.readFileSync(path.join(__dirname, '../workflows/main-review-policy.yml'), 'utf8');
  assert.match(workflow, /ref: main/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /cancel-in-progress: false/);
  assert.match(workflow, /MAIN_REVIEW_POLICY_AUTOMERGE/);
  assert.doesNotMatch(workflow, /pull_request\.head|download-artifact|secrets\./);
});
