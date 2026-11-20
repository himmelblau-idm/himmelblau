'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { run, evaluate, ciReasons, sensitiveChanges, testingConfirmation, command, REQUIRED_CI,
  sharedHeadCheckEligible, sharedHeadAutoEligible } = require('./review-policy.js');

const SHA = 'a'.repeat(40);
const OLD = 'b'.repeat(40);
const user = login => ({ login, type: 'User' });
const bot = login => ({ login, type: 'Bot' });
const pr = () => ({ number: 1, state: 'open', draft: false, user: user('author'),
  head: { sha: SHA }, base: { ref: 'main', sha: OLD }, changed_files: 1, mergeable: true, mergeable_state: 'clean' });
const review = (login = 'maintainer', extra = {}) => ({ id: 1, user: user(login), state: 'APPROVED', commit_id: SHA, body: '', ...extra });
const check = (name, extra = {}) => ({ id: 1, name, app: { id: 15368 }, status: 'completed', conclusion: 'success', ...extra });
const snapshot = () => ({ pr: pr(), authorCanWrite: true, permissions: { maintainer: true },
  reviews: [review()], threads: [], checks: [], comments: [], files: [{ filename: 'src/selinux/src/himmelblaud.te' }] });
const confirmation = (extra = {}) => ({ id: 10, user: user('maintainer'), body: `/confirm-tested ${SHA}`,
  html_url: 'https://github.com/himmelblau-idm/himmelblau/pull/1#issuecomment-10', ...extra });
const coderabbitCheck = () => check('CodeRabbit', { app: { id: 347564, slug: 'coderabbitai' } });
const coderabbitReview = () => review('coderabbitai[bot]', { user: bot('coderabbitai[bot]'), state: 'COMMENTED' });
const coderabbitSummary = () => ({ id: 1, user: bot('coderabbitai[bot]'), body:
  `<!-- change_assessment_commit:"${SHA}" -->\n<!-- recent_review_status_start -->\nNo actionable comments were generated in the recent review.\n<!-- recent_review_status_end -->` });
const codexReview = (extra = {}) => review('chatgpt-codex-connector[bot]', {
  user: bot('chatgpt-codex-connector[bot]'), state: 'COMMENTED',
  body: "### Codex Review: Didn't find any major issues.", ...extra });

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
    codexReview({ id: 3 })],
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
test('CodeRabbit APPROVED still requires check and clean summary', () => {
  const s = { ...snapshot(), reviews: [review('coderabbitai[bot]', {
    user: bot('coderabbitai[bot]'), state: 'APPROVED' })] };
  assert.equal(evaluate(s).eligible, false);
  s.checks = [coderabbitCheck()];
  assert.equal(evaluate(s).eligible, false);
  s.comments = [coderabbitSummary()];
  assert.equal(evaluate(s).eligible, true);
});
test('stale bot review does not erase a current delegated approval', () => {
  const s = { ...snapshot(), reviews: [
    review('maintainer', { body: '<!-- review-policy:ai:codex -->' }),
    review('chatgpt-codex-connector[bot]', { id: 2, user: bot('chatgpt-codex-connector[bot]'),
      commit_id: OLD, state: 'COMMENTED', body: "Codex Review: Didn't find any major issues." }),
  ] };
  assert.equal(evaluate(s).eligible, true);
  assert.ok(evaluate(s).reviewers.includes('ai:codex'));
});
test('non-clean current-head bot review does not erase delegated approval', () => {
  const s = { ...snapshot(), reviews: [
    review('maintainer', { body: '<!-- review-policy:ai:codex -->' }),
    review('chatgpt-codex-connector[bot]', { id: 2, user: bot('chatgpt-codex-connector[bot]'),
      state: 'COMMENTED', body: 'Codex Review: Found major issues.' }),
  ] };
  assert.equal(evaluate(s).eligible, true);
  assert.ok(evaluate(s).reviewers.includes('ai:codex'));
});
test('inconclusive bot APPROVED does not erase delegated approval', () => {
  const s = { ...snapshot(), reviews: [
    review('maintainer', { body: '<!-- review-policy:ai:codex -->' }),
    review('chatgpt-codex-connector[bot]', { id: 2, user: bot('chatgpt-codex-connector[bot]'),
      state: 'APPROVED', body: '' }),
  ] };
  assert.equal(evaluate(s).eligible, true);
  assert.ok(evaluate(s).reviewers.includes('ai:codex'));
});
test('head and synthetic merge CI are evaluated independently', () => {
  const checks = REQUIRED_CI.map(name => check(name));
  const merge = 'c'.repeat(40);
  const mergeChecks = REQUIRED_CI.map((name, i) => check(name, { id: 10 + i, head_sha: merge }));
  assert.deepEqual(ciReasons(checks, [], mergeChecks, []), []);
  const failingHead = [...checks, check('optional', { id: 99, conclusion: 'failure' })];
  const passingMerge = [...mergeChecks, check('optional', { id: 100, conclusion: 'success', head_sha: merge })];
  assert.notEqual(ciReasons(failingHead, [], passingMerge, []).length, 0);
  const headStatuses = [{ id: 1, context: 'ext', state: 'failure' }];
  const mergeStatuses = [{ id: 2, context: 'ext', state: 'success' }];
  assert.notEqual(ciReasons(checks, headStatuses, mergeChecks, mergeStatuses).length, 0);
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
test('Codex and Copilot APPROVED still require their clean review bodies', () => {
  const copilot = { ...snapshot(), tested: { by: 'maintainer' },
    reviews: [review('copilot-pull-request-reviewer[bot]', {
      user: bot('copilot-pull-request-reviewer[bot]'), state: 'APPROVED' })] };
  assert.equal(evaluate(copilot).autoEligible, false);
  copilot.reviews[0].body = '<!-- ccr-overview-v2 -->\n\n### 🟢 Ready to approve\n\n**No open issues** 🎉';
  assert.equal(evaluate(copilot).autoEligible, true);
  const codex = { ...snapshot(), tested: { by: 'maintainer' },
    reviews: [review('chatgpt-codex-connector[bot]', {
      user: bot('chatgpt-codex-connector[bot]'), state: 'APPROVED' })] };
  assert.equal(evaluate(codex).autoEligible, false);
  codex.reviews[0].body = "### Codex Review: Didn't find any major issues.";
  assert.equal(evaluate(codex).autoEligible, true);
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
  unresolved = false, ciFailure = false, syntheticCI = false, latestRabbitPending = false,
  outside = false, sensitive = false, confirmed = true, sponsored = false, filesIncomplete = false } = {}) {
  const calls = [];
  const initial = pr();
  initial.mergeable_state = mergeState;
  if (sponsored) initial.user = bot('companion[bot]');
  if (syntheticCI) initial.merge_commit_sha = 'c'.repeat(40);
  let reads = 0;
  const github = {
    rest: {
      pulls: {
        list: async () => [initial],
        get: async () => ({ data: { ...initial, head: { sha: changeHead && ++reads > 1 ? OLD : SHA },
          base: { ...initial.base, ref: changeBase && ++reads > 1 ? 'stable-4.x' : 'main' } } }),
        listReviews: async () => latestRabbitPending ? [coderabbitReview()]
          : outside ? [review(), review('other', { id: 2 })] : [review()],
        listFiles: async () => filesIncomplete ? [] : [{ filename: sensitive ? '.github/workflows/ci.yml' : 'src/selinux/src/himmelblaud.te' }],
        merge: async args => { calls.push(['merge', args]); return { data: { merged: true, message: 'merged' } }; },
      },
      repos: {
        getCollaboratorPermissionLevel: async ({ username }) => {
          if (permissionError) throw Object.assign(new Error('forbidden'), { status: 403 });
          return { data: { permission: outside && username === 'author' ? 'read' : 'write' } };
        },
        listCommitStatusesForRef: async () => [],
      },
      issues: { listComments: async () => [
        ...(latestRabbitPending ? [coderabbitSummary()] : []),
        ...(confirmed ? [confirmation()] : []),
        ...(sponsored ? [confirmation({ id: 11, body: `/sponsor-ai ${SHA}` })] : []),
      ] },
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
  assert.equal(h.calls.filter(c => c[0] === 'threads').length, 4);
  const merge = h.calls.find(c => c[0] === 'merge')[1];
  assert.equal(merge.sha, SHA); assert.equal(merge.merge_method, 'squash');
});
test('coordinator report-only mode never merges', async () => {
  const h = harness(); await run(h);
  assert.equal(h.calls.some(c => c[0] === 'merge'), false);
  assert.equal(h.calls.find(c => c[0] === 'check')[1].conclusion, 'success');
});
test('shared head SHA fails closed until every open main PR on that commit passes', () => {
  const eligible = { policy: { eligible: true, autoEligible: true } };
  const blocked = { policy: { eligible: false, autoEligible: false } };
  assert.equal(sharedHeadCheckEligible([eligible], eligible.policy), true);
  assert.equal(sharedHeadCheckEligible([eligible, blocked], eligible.policy), false);
  assert.equal(sharedHeadAutoEligible([eligible, blocked], eligible.policy), false);
  const revalidated = { policy: { eligible: true, autoEligible: true },
    finalPolicy: { eligible: false, autoEligible: false } };
  assert.equal(sharedHeadAutoEligible([eligible, revalidated], eligible.policy), false);
});
test('shared head sibling gains changes request during final peer revalidation', async () => {
  const ready1 = { ...pr(), number: 1 };
  const ready2 = { ...pr(), number: 2 };
  const reviewReads = new Map();
  const calls = [];
  const github = {
    rest: {
      pulls: {
        list: async () => [ready1, ready2],
        get: async ({ pull_number }) => ({ data: { ...(pull_number === 1 ? ready1 : ready2),
          mergeable: true, mergeable_state: 'clean' } }),
        listReviews: async ({ pull_number }) => {
          const count = (reviewReads.get(pull_number) || 0) + 1;
          reviewReads.set(pull_number, count);
          if (count > 1 && pull_number === 1) return [review('maintainer', { state: 'CHANGES_REQUESTED' })];
          return [review()];
        },
        listFiles: async () => [{ filename: 'src/selinux/src/himmelblaud.te' }],
        merge: async args => { calls.push(['merge', args]); return { data: { merged: true } }; },
      },
      repos: {
        getCollaboratorPermissionLevel: async () => ({ data: { permission: 'write' } }),
        listCommitStatusesForRef: async () => [],
      },
      issues: { listComments: async () => [confirmation()] },
      checks: {
        listForRef: async () => REQUIRED_CI.map(name => check(name)),
        create: async args => { calls.push(['check', args]); return { data: { id: args.external_id === 'main-review-policy:1' ? 1 : 2 } }; },
        update: async args => { calls.push(['update', args]); },
      },
    },
    paginate: async (method, args) => method(args),
    graphql: async () => ({ repository: { pullRequest: { reviewThreads: {
      nodes: [{ isResolved: true }], pageInfo: { hasNextPage: false },
    } } } }),
  };
  const core = { info: () => {}, error: () => {}, setFailed: () => {} };
  await run({ github, core, context: { repo: { owner: 'himmelblau-idm', repo: 'himmelblau' } }, merge: true });
  assert.equal(calls.some(c => c[0] === 'merge'), false);
});
test('shared head automerge uses current PR CI, not a sibling merge check', async () => {
  const mergeSha1 = 'c'.repeat(40);
  const mergeSha2 = 'd'.repeat(40);
  const ready1 = { ...pr(), number: 1, merge_commit_sha: mergeSha1 };
  const ready2 = { ...pr(), number: 2, merge_commit_sha: mergeSha2 };
  const calls = [];
  const github = {
    rest: {
      pulls: {
        list: async () => [ready1, ready2],
        get: async ({ pull_number }) => ({ data: { ...(pull_number === 1 ? ready1 : ready2),
          mergeable: true, mergeable_state: 'clean' } }),
        listReviews: async () => [review()],
        listFiles: async () => [{ filename: 'src/selinux/src/himmelblaud.te' }],
        merge: async args => { calls.push(['merge', args]); return { data: { merged: true } }; },
      },
      repos: {
        getCollaboratorPermissionLevel: async () => ({ data: { permission: 'write' } }),
        listCommitStatusesForRef: async () => [],
      },
      issues: { listComments: async ({ issue_number }) => issue_number === 1 ? [confirmation()] : [confirmation({
        id: 11, body: `/confirm-tested ${SHA}`, html_url: 'https://github.com/himmelblau-idm/himmelblau/pull/2#issuecomment-11',
      })] },
      checks: {
        listForRef: async ({ ref }) => {
          const mandatory = REQUIRED_CI.map(name => check(name));
          if (ref === mergeSha2) return [...mandatory, check('Extra', { conclusion: 'failure' })];
          return mandatory;
        },
        create: async args => { calls.push(['check', args]); return { data: { id: args.external_id === 'main-review-policy:1' ? 1 : 2 } }; },
        update: async args => { calls.push(['update', args]); },
      },
    },
    paginate: async (method, args) => method(args),
    graphql: async () => ({ repository: { pullRequest: { reviewThreads: {
      nodes: [{ isResolved: true }], pageInfo: { hasNextPage: false },
    } } } }),
  };
  const core = { info: () => {}, error: () => {}, setFailed: () => {} };
  await run({ github, core, context: { repo: { owner: 'himmelblau-idm', repo: 'himmelblau' } }, merge: true });
  assert.equal(calls.filter(c => c[0] === 'merge').length, 1);
  assert.equal(calls.find(c => c[0] === 'merge')[1].pull_number, 1);
});
test('failed evaluation on a shared head blocks eligible sibling automerge', async () => {
  const ready = { ...pr(), number: 1 };
  const broken = { ...pr(), number: 2 };
  const calls = [];
  let listFilesReads = 0;
  const github = {
    rest: {
      pulls: {
        list: async () => [ready, broken],
        get: async ({ pull_number }) => {
          if (pull_number === 2) throw Object.assign(new Error('api down'), { status: 500 });
          return { data: { ...ready, mergeable: true, mergeable_state: 'clean' } };
        },
        listReviews: async () => [review()],
        listFiles: async ({ pull_number }) => {
          listFilesReads++;
          if (pull_number === 2) throw Object.assign(new Error('api down'), { status: 500 });
          return [{ filename: 'src/selinux/src/himmelblaud.te' }];
        },
        merge: async args => { calls.push(['merge', args]); return { data: { merged: true } }; },
      },
      repos: {
        getCollaboratorPermissionLevel: async () => ({ data: { permission: 'write' } }),
        listCommitStatusesForRef: async () => [],
      },
      issues: { listComments: async () => [confirmation()] },
      checks: {
        listForRef: async () => REQUIRED_CI.map(name => check(name)),
        create: async args => { calls.push(['check', args]); return { data: { id: 1 } }; },
        update: async args => { calls.push(['update', args]); },
      },
    },
    paginate: async (method, args) => method(args),
    graphql: async () => ({ repository: { pullRequest: { reviewThreads: {
      nodes: [{ isResolved: true }], pageInfo: { hasNextPage: false },
    } } } }),
  };
  const core = { info: () => {}, error: () => {}, setFailed: v => calls.push(['error', v]) };
  await run({ github, core, context: { repo: { owner: 'himmelblau-idm', repo: 'himmelblau' } }, merge: true });
  assert.equal(calls.some(c => c[0] === 'merge'), false);
});
test('shared head blocks automerge when a sibling races during evaluation', async () => {
  const racedSha = OLD;
  const ready = { ...pr(), number: 1, head: { sha: racedSha } };
  const racing = { ...pr(), number: 2, head: { sha: racedSha } };
  const pulled = new Map();
  const calls = [];
  const github = {
    rest: {
      pulls: {
        list: async () => [ready, racing],
        get: async ({ pull_number }) => {
          const count = (pulled.get(pull_number) || 0) + 1;
          pulled.set(pull_number, count);
          if (pull_number === 2 && count > 1) {
            return { data: { ...racing, head: { sha: SHA }, mergeable: true, mergeable_state: 'clean' } };
          }
          return { data: { ...(pull_number === 1 ? ready : racing), mergeable: true, mergeable_state: 'clean' } };
        },
        listReviews: async () => [review('maintainer', { commit_id: racedSha })],
        listFiles: async () => [{ filename: 'src/selinux/src/himmelblaud.te' }],
        merge: async args => { calls.push(['merge', args]); return { data: { merged: true } }; },
      },
      repos: {
        getCollaboratorPermissionLevel: async () => ({ data: { permission: 'write' } }),
        listCommitStatusesForRef: async () => [],
      },
      issues: { listComments: async () => [confirmation({ body: `/confirm-tested ${racedSha}` })] },
      checks: {
        listForRef: async () => REQUIRED_CI.map(name => check(name)),
        create: async args => { calls.push(['check', args]); return { data: { id: 1 } }; },
        update: async args => { calls.push(['update', args]); },
      },
    },
    paginate: async (method, args) => method(args),
    graphql: async () => ({ repository: { pullRequest: { reviewThreads: {
      nodes: [{ isResolved: true }], pageInfo: { hasNextPage: false },
    } } } }),
  };
  const core = { info: () => {}, error: () => {}, setFailed: () => {} };
  await run({ github, core, context: { repo: { owner: 'himmelblau-idm', repo: 'himmelblau' } }, merge: true });
  assert.equal(calls.some(c => c[0] === 'merge'), false);
  assert.ok(calls.some(c => (c[0] === 'check' || c[0] === 'update') && c[1].conclusion === 'failure'));
});
test('eligible writer PR cannot automerge when another main PR shares its head', async () => {
  const ready = { ...pr(), number: 1 };
  const blocked = { ...pr(), number: 2, user: user('outsider') };
  blocked.changed_files = 1;
  const calls = [];
  const github = {
    rest: {
      pulls: {
        list: async () => [ready, blocked],
        get: async ({ pull_number }) => ({ data: pull_number === 1 ? { ...ready, mergeable: true, mergeable_state: 'clean' }
          : { ...blocked, mergeable: true, mergeable_state: 'clean' } }),
        listReviews: async ({ pull_number }) => pull_number === 1 ? [review()] : [review()],
        listFiles: async () => [{ filename: 'src/selinux/src/himmelblaud.te' }],
        merge: async args => { calls.push(['merge', args]); return { data: { merged: true } }; },
      },
      repos: {
        getCollaboratorPermissionLevel: async ({ username }) => ({
          data: { permission: username === 'outsider' ? 'read' : 'write' },
        }),
        listCommitStatusesForRef: async () => [],
      },
      issues: { listComments: async ({ issue_number }) => issue_number === 1 ? [confirmation()] : [] },
      checks: {
        listForRef: async () => REQUIRED_CI.map(name => check(name)),
        create: async args => { calls.push(['check', args]); return { data: { id: args.external_id === 'main-review-policy:1' ? 1 : 2 } }; },
        update: async args => { calls.push(['update', args]); },
      },
    },
    paginate: async (method, args) => method(args),
    graphql: async () => ({ repository: { pullRequest: { reviewThreads: {
      nodes: [{ isResolved: true }], pageInfo: { hasNextPage: false },
    } } } }),
  };
  const core = { info: () => {}, error: () => {}, setFailed: () => {} };
  await run({ github, core, context: { repo: { owner: 'himmelblau-idm', repo: 'himmelblau' } }, merge: true });
  const published = calls.filter(c => c[0] === 'check' || c[0] === 'update');
  assert.equal(published.length, 2);
  assert.ok(published.every(([, args]) => args.conclusion === 'failure'));
  assert.equal(calls.some(c => c[0] === 'merge'), false);
});
test('race, blocked state, failed CI, permission errors and paginated unresolved threads prevent merge', async () => {
  for (const options of [{ changeHead: true }, { changeBase: true }, { mergeState: 'behind' },
    { mergeState: 'blocked' }, { permissionError: true }, { unresolved: true }, { ciFailure: true }, { latestRabbitPending: true },
    { outside: true }, { sensitive: true }, { confirmed: false }, { filesIncomplete: true }]) {
    const h = harness(options); await run({ ...h, merge: true });
    assert.equal(h.calls.some(c => c[0] === 'merge'), false, JSON.stringify(options));
  }
});
test('explicitly writer-sponsored bot can automerge after review and testing', async () => {
  const h = harness({ sponsored: true }); await run({ ...h, merge: true });
  assert.equal(h.calls.some(c => c[0] === 'merge'), true);
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
test('failed PR reload publishes a blocking policy check using the list summary head', async () => {
  const h = harness();
  h.github.rest.pulls.get = async () => { throw Object.assign(new Error('api down'), { status: 500 }); };
  await run(h);
  assert.equal(h.calls.find(c => c[0] === 'check')?.[1]?.conclusion, 'failure');
  assert.equal(h.calls.find(c => c[0] === 'error')?.[1], '1 PR policy evaluation(s) failed.');
});
test('workflow uses main checkout and no untrusted code or credentials persistence', () => {
  const workflow = fs.readFileSync(path.join(__dirname, '../workflows/main-review-policy.yml'), 'utf8');
  assert.match(workflow, /ref: main/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /cancel-in-progress: false/);
  assert.match(workflow, /MAIN_REVIEW_POLICY_AUTOMERGE/);
  assert.doesNotMatch(workflow, /pull_request\.head|download-artifact|secrets\./);
});

test('sensitive runtime, configuration and all GitHub paths require human review', () => {
  const protectedPaths = ['src/pam/src/lib.rs', 'src/nss/scripts/postinst', 'src/daemon/src/daemon.rs',
    'src/common/docs-xml/example.xml', 'src/idmap/src/lib.rs', 'src/broker/src/main.rs',
    'src/broker-client/src/lib.rs', 'src/sso/src/main.rs', 'src/cli/src/main.rs',
    'src/policies/src/scripts_ext.rs', '.github/ISSUE_TEMPLATE/bug_report.yml',
    '.github/scripts/review-policy.js', '.github/workflows/ci.yml',
    'platform/debian/pam-config-unseal', 'platform/opensuse/pam-config', 'platform/el/sshd_config',
    'platform/debian/himmelblaud.service', 'platform/opensuse/himmelblaud-tasks.socket',
    'src/sshd-config/scripts/postinst', 'scripts/gen_authselect.py', 'scripts/gen_servicefiles.py',
    'platform/systemd/himmelblaud.socket', 'nix/modules/himmelblau.nix',
    'scripts/obs_update.py', 'src/overrides/reqwest/0.12.24/src/lib.rs',
    'src/o365/build.rs', 'supply-chain/audits.toml'];
  for (const filename of protectedPaths) {
    const s = { ...snapshot(), files: [{ filename }], tested: { by: 'maintainer' },
      reviews: [codexReview()] };
    assert.equal(evaluate(s).eligible, false, filename);
    s.reviews.push(review('maintainer', { id: 2 }));
    assert.equal(evaluate(s).eligible, true, filename);
    assert.equal(evaluate(s).autoEligible, false, filename);
  }
});
test('SELinux, experimental orchestrator and Collabora remain AI eligible', () => {
  for (const filename of ['src/selinux/src/himmelblaud.te', 'src/orchestrator/src/communication.rs',
    'src/collabora/src/server.rs', 'README.md', 'scripts/gen_dockerfiles.py', 'src/sso-policies/src/firefox/policies.json']) {
    const s = { ...snapshot(), files: [{ filename }], tested: { by: 'maintainer' },
      reviews: [codexReview()] };
    assert.equal(evaluate(s).autoEligible, true, filename);
  }
});
test('renames out of protected code stay sensitive; incomplete file enumeration blocks even humans', () => {
  const s = { ...snapshot(), tested: { by: 'maintainer' },
    files: [{ filename: 'src/collabora/src/moved.rs', previous_filename: 'src/common/src/auth.rs' }] };
  assert.equal(evaluate(s).eligible, true);
  assert.equal(evaluate(s).autoEligible, false);
  for (const files of [undefined, []]) {
    assert.equal(evaluate({ ...s, files }).eligible, false);
  }
  assert.equal(evaluate({ ...s, pr: { ...s.pr, changed_files: 3001 } }).eligible, false);
});
test('security dependencies and source changes require humans, ordinary version bumps do not', () => {
  for (const patch of [undefined, '-libhimmelblau = "0.8.44"\n+libhimmelblau = "0.8.45"',
    '-sha2 = "0.10.8"\n+sha2 = "0.10.9"',
    '-authenticator = "0.1.0"\n+authenticator = "0.1.1"',
    '-libwebauthn = "0.1.0"\n+libwebauthn = "0.1.1"',
    '-argon2 = "0.5.3"\n+argon2 = "0.5.4"',
    '-pbkdf2 = "0.12.2"\n+pbkdf2 = "0.12.3"',
    '-rpassword = "7.3.1"\n+rpassword = "7.3.2"',
    '+newdep = { git = "https://example.com/dep" }', '+build = "script.rs"',
    '+newdep = "1.0"', '-olddep = "1.0"\n+newdep = "1.0"',
    '+dep = { version = "1", features = ["danger"] }']) {
    assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml', patch }]), ['Cargo.toml']);
  }
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '-clap = "4.5"\n+clap = "4.6"' }]), ['Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: ' [dependencies]\n-clap = "4.5"\n+clap = "4.6"' }]), []);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: ' [workspace.dependencies]\n-clap = "4.5"\n+clap = "4.6"' }]), []);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: ' [workspace.dev-dependencies]\n-tokio = "1.40"\n+tokio = "1.41"' }]), []);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: ' [workspace.build-dependencies]\n-cc = "1.0"\n+cc = "1.1"' }]), []);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'src/fxhash/Cargo.toml',
    patch: ' [package]\n-version = "0.1.0"\n+version = "0.1.1"' }]), []);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: ' [workspace.package]\n-version = "3.1.14"\n+version = "3.1.15"' }]), []);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '-resolver = "2"\n+resolver = "3"' }]), ['Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '-edition = "2021"\n+edition = "2024"' }]), ['Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '-rust-version = "1.89"\n+rust-version = "1.90"' }]), ['Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '-dep = { version = "1", features = ["32bit"] }\n+dep = { version = "1", features = ["64bit"] }' }]), ['Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'src/o365/Cargo.toml',
    patch: '-post_install_script = "scripts/postinst"\n+post_install_script = "scripts/postrm"' }]), ['src/o365/Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'src/daemon/Cargo.toml',
    patch: '-maintainer-scripts = "scripts"\n+maintainer-scripts = "evil"' }]), ['src/daemon/Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'platform/debian/himmelblaud.service' }]), ['platform/debian/himmelblaud.service']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '-rustc-workspace-wrapper = "none"\n+rustc-workspace-wrapper = "sccache"' }]), ['Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '-version = "0.1.0"\n+version = "0.1.1"' }]), ['Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '@@ -1,3 +1,3 @@\n [dependencies]\n-clap = "4.5"\n+clap = "4.6"\n'
      + '@@ -10,3 +10,3 @@\n-description = "1 old"\n+description = "2 new"' }]), ['Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '@@ -1,3 +1,3 @@\n [dependencies]\n-clap = "4.5"\n+clap = "4.6"\n'
      + '@@ -10,3 +10,3 @@\n-version = "0.1.0"\n+version = "0.1.1"' }]), ['Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '@@ -1,3 +1,3 @@\n [dependencies]\n-clap = "4.5"\n+clap = "4.6"\n'
      + '@@ -10,3 +10,3 @@\n [package]\n-version = "0.1.0"\n+version = "0.1.1"' }]), []);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: '@@ -1,3 +1,3 @@\n [dependencies]\n-clap = "4.5"\n+clap = "4.6"\n'
      + '@@ -10,4 +10,4 @@\n [package]\n-description = "1 old"\n+description = "2 new"' }]), ['Cargo.toml']);
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.toml',
    patch: ' [dependencies]\n-clap = "4.5"\n+clap = "4.6"\n-description = "1 old"\n+description = "2 new"' }]), ['Cargo.toml']);
  for (const name of ['sha2', 'authenticator', 'libwebauthn', 'totp-rs', 'aes', 'aead']) {
    assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Cargo.lock',
      patch: ` name = "${name}"\n-version = "0.1.0"\n+version = "0.1.1"` }]), ['Cargo.lock'], name);
  }
  for (const filename of ['Makefile', 'flake.nix', 'default.nix', 'shell.nix']) {
    assert.deepEqual(sensitiveChanges(pr(), [{ filename, patch: '+EXTRA = value' }]), [filename]);
  }
  assert.deepEqual(sensitiveChanges(pr(), [{ filename: 'Makefile',
    patch: '-@./scripts/gen_servicefiles.py\n+@./scripts/gen_servicefiles.py --static-user root' }]), ['Makefile']);
});
test('manual eligibility does not require testing, but automatic eligibility does', () => {
  const s = snapshot();
  assert.equal(evaluate(s).eligible, true);
  assert.equal(evaluate(s).autoEligible, false);
  s.tested = { by: 'maintainer' };
  assert.equal(evaluate(s).autoEligible, true);
  s.authorCanWrite = false;
  s.reviews.push(review('other', { id: 2 })); s.permissions.other = true;
  assert.equal(evaluate(s).eligible, true);
  assert.equal(evaluate(s).autoEligible, false);
});
test('only a writer can sponsor a bot, for the current head, without relaxing outside human PR rules', () => {
  const s = { ...snapshot(), authorCanWrite: false, tested: { by: 'maintainer' },
    pr: { ...pr(), user: bot('companion[bot]') },
    comments: [confirmation({ body: `/sponsor-ai ${SHA}` })] };
  assert.equal(evaluate(s).autoEligible, true);
  s.comments.push(confirmation({ id: 11, body: `/revoke-sponsor ${SHA}` }));
  assert.equal(evaluate(s).eligible, false);
  s.comments.pop(); s.comments[0].user = user('stranger');
  assert.equal(evaluate(s).eligible, false);
  s.comments[0].user = user('maintainer'); s.comments[0].body = `/sponsor-ai ${OLD}`;
  assert.equal(evaluate(s).eligible, false);
  s.comments[0].body = `/sponsor-ai ${SHA}`; s.pr.user = user('outside-human');
  assert.equal(evaluate(s).eligible, false);
});

function evidenceHarness(comments, options = {}) {
  return { owner: 'himmelblau-idm', repo: 'himmelblau', pr: pr(), comments,
    permissions: { maintainer: true }, github: {
      rest: { issues: { getComment: async () => {
        if (options.missing) throw Object.assign(new Error('deleted'), { status: 404 });
        return { data: { user: options.bot ? bot('tester[bot]') : user('tester'),
          body: options.empty ? '' : 'Tested this build on Rocky 8; SSH now works.',
          issue_url: `https://api.github.com/repos/himmelblau-idm/himmelblau/issues/${options.wrongIssue ? 999 : options.issue || 1}` } };
      } } },
      graphql: async (_query, args) => ({ repository: { pullRequest: { closingIssuesReferences: {
        nodes: args.cursor && options.linked ? [{ number: options.issue,
          repository: { nameWithOwner: 'himmelblau-idm/himmelblau' } }] : [],
        pageInfo: { hasNextPage: !args.cursor, endCursor: 'page2' },
      } } } }),
    } };
}
test('testing confirmation requires explicit writer command and exact current SHA', async () => {
  assert.ok(await testingConfirmation(evidenceHarness([confirmation()])));
  for (const extra of [{ user: user('stranger') }, { user: bot('maintainer') },
    { body: `/confirm-tested ${OLD}` }, { body: `/confirm-tested ${SHA.slice(0, 10)}` },
    { body: `> /confirm-tested ${SHA}` }, { body: `\u0060\u0060\u0060\n/confirm-tested ${SHA}\n\u0060\u0060\u0060` },
    { body: 'Works now!' }]) {
    assert.equal(await testingConfirmation(evidenceHarness([confirmation(extra)])), null);
  }
  assert.equal(command(confirmation({ body: `/sponsor-ai ${SHA} https://example.com` }), SHA), null);
});
test('latest writer testing revocation wins, including edits; deleting confirmation leaves no grant', async () => {
  const comments = [confirmation({ updated_at: '2026-11-13T10:00:00Z' }),
    confirmation({ id: 11, body: `/revoke-tested ${SHA}`, updated_at: '2026-11-13T11:00:00Z' })];
  assert.equal(await testingConfirmation(evidenceHarness(comments)), null);
  comments[0].updated_at = '2026-11-13T12:00:00Z';
  assert.ok(await testingConfirmation(evidenceHarness(comments)));
  assert.equal(await testingConfirmation(evidenceHarness([])), null);
});
test('testing evidence may come from this PR or a linked issue, including paginated closing links', async () => {
  for (const [kind, issue, linked] of [['pull', 1, false], ['issues', 42, true]]) {
    const c = confirmation({ body: `/confirm-tested ${SHA} https://github.com/himmelblau-idm/himmelblau/${kind}/${issue}#issuecomment-20` });
    const result = await testingConfirmation(evidenceHarness([c], { issue, linked }));
    assert.equal(result.tester, 'tester');
  }
  const c = confirmation({ body: `/confirm-tested ${SHA} https://github.com/himmelblau-idm/himmelblau/issues/42#issuecomment-20` });
  const h = evidenceHarness([c], { issue: 42 }); h.pr.body = 'Bug report: https://github.com/himmelblau-idm/himmelblau/issues/42';
  assert.ok(await testingConfirmation(h));
});
test('unrelated, foreign, bot-authored, deleted or mismatched evidence cannot authorize automatic merging', async () => {
  const base = `https://github.com/himmelblau-idm/himmelblau/pull/1#issuecomment-20`;
  for (const url of [base.replace('/pull/1', '/pull/2'), base.replace('/pull/1', '/issues/42'),
    base.replace('himmelblau-idm', 'someone-else'), base.replace('github.com', 'github.com.evil.example'),
    base.replace('#issuecomment-20', '#discussion_r20'), `${base}&extra`,
    base.replace('/pull/1#', '/pull/1?x=y#')]) {
    assert.equal(await testingConfirmation(evidenceHarness([confirmation({ body: `/confirm-tested ${SHA} ${url}` })])), null);
  }
  for (const options of [{ bot: true }, { missing: true }, { wrongIssue: true }, { empty: true }]) {
    assert.equal(await testingConfirmation(evidenceHarness([confirmation({ body: `/confirm-tested ${SHA} ${base}` })], options)), null);
  }
});
test('revoked sponsorship at final evaluation prevents automerge while testing confirmation remains', async () => {
  const h = harness({ sponsored: true });
  let reads = 0;
  const original = h.github.rest.issues.listComments;
  h.github.rest.issues.listComments = async () => {
    if (++reads === 1) return original();
    // Keep /confirm-tested so merge failure is attributable to sponsorship revalidation.
    return (await original()).filter(c => !(c.body || '').startsWith('/sponsor-ai '));
  };
  await run({ ...h, merge: true });
  assert.equal(h.calls.some(c => c[0] === 'merge'), false);
});
test('revoked testing, new findings, and CI reruns at final evaluation prevent merging', async () => {
  for (const type of ['testing', 'review', 'ci', 'permissions']) {
    const h = harness({ sponsored: false });
    let reads = 0;
    if (type === 'testing') {
      const original = h.github.rest.issues.listComments;
      h.github.rest.issues.listComments = async () => {
        if (++reads === 1) return original();
        return [];
      };
    } else if (type === 'review') {
      h.github.rest.pulls.listReviews = async () => ++reads === 1 ? [review()] : [review('maintainer', { state: 'CHANGES_REQUESTED' })];
    } else if (type === 'permissions') {
      const original = h.github.rest.issues.listComments;
      h.github.rest.issues.listComments = async () => {
        if (++reads > 1) h.github.rest.repos.getCollaboratorPermissionLevel = async () => ({ data: { permission: 'read' } });
        return original();
      };
    } else {
      const original = h.github.rest.checks.listForRef;
      h.github.rest.checks.listForRef = async args => ++reads === 1 ? original(args)
        : [check('Build', { status: 'queued', conclusion: null })];
    }
    await run({ ...h, merge: true });
    assert.equal(h.calls.some(c => c[0] === 'merge'), false, type);
  }
});


test('event scans include same-head siblings but exclude unrelated PRs', () => {
  const { affectedPRs } = require('./review-policy.js');
  const prs = [pr(), { ...pr(), number: 2 }, { ...pr(), number: 3, head: { sha: OLD } }];
  for (const context of [
    { eventName: 'pull_request_target', payload: { pull_request: { number: 1 } } },
    { eventName: 'issue_comment', payload: { issue: { number: 1, pull_request: {} } } },
    { eventName: 'workflow_run', payload: { workflow_run: { head_sha: SHA, pull_requests: [] } } },
    { eventName: 'workflow_run', payload: { workflow_run: { pull_requests: [{ number: 1 }] } } },
    { eventName: 'status', payload: { sha: SHA } },
    { eventName: 'check_run', payload: { check_run: { head_sha: SHA } } },
  ]) assert.deepEqual(affectedPRs(prs, context).map(p => p.number), [1, 2]);
  for (const context of [
    { eventName: 'schedule' }, { eventName: 'workflow_dispatch' },
    { eventName: 'issue_comment', payload: { issue: { number: 99 } } },
    { eventName: 'workflow_run', payload: { workflow_run: {} } },
  ]) assert.deepEqual(affectedPRs(prs, context), prs);
  assert.deepEqual(affectedPRs(prs, { eventName: 'status', payload: { sha: 'c'.repeat(40) } }), []);
});

test('targeted coordinator does not fetch unrelated PR details', async () => {
  const h = harness();
  h.github.rest.pulls.list = async () => [pr(), { ...pr(), number: 2, head: { sha: OLD } }];
  const get = h.github.rest.pulls.get;
  h.github.rest.pulls.get = async args => {
    assert.equal(args.pull_number, 1);
    return get(args);
  };
  h.context.eventName = 'workflow_run';
  h.context.payload = { workflow_run: { head_sha: SHA, pull_requests: [] } };
  await run(h);
  assert.equal(h.calls.filter(c => c[0] === 'check').length, 1);
});

test('unchanged checks avoid writes, but a revoked approval updates the result', async () => {
  const h = harness();
  await run(h);
  const published = h.calls.find(c => c[0] === 'check')[1];
  const list = h.github.rest.checks.listForRef;
  h.github.rest.checks.listForRef = async args => [...await list(args),
    { ...published, id: 99, app: { id: 15368 } }];
  h.calls.length = 0;
  await run(h);
  assert.equal(h.calls.some(c => ['check', 'update'].includes(c[0])), false);
  h.github.rest.pulls.listReviews = async () => [];
  await run(h);
  assert.equal(h.calls.find(c => c[0] === 'update')[1].conclusion, 'failure');
});
