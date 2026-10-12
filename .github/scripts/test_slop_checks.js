'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const run = require('./slop-checks.js');
const fs = require('node:fs');
const path = require('node:path');

const repository = 'himmelblau-idm/himmelblau';
function maintenancePr() {
  return {
    number: 1815,
    user: { login: 'himmelblau-stable-maintenance[bot]', type: 'Bot' },
    head: { ref: 'automation/stable-maintenance/stable-4.x-20261012-abcd',
      repo: { full_name: repository } },
    base: { ref: 'stable-4.x' },
  };
}

test('only the repository maintenance bot on its expected branches is exempt', () => {
  assert.equal(run.isExempt(maintenancePr(), repository).exempt, true);
  for (const mutate of [
    (pr) => { pr.user.login = 'external-contributor'; },
    (pr) => { pr.user.type = 'User'; },
    (pr) => { pr.head.repo.full_name = 'external/fork'; },
    (pr) => { pr.head.ref = 'external-branch'; },
    (pr) => { pr.base.ref = 'main'; },
  ]) {
    const pr = maintenancePr();
    mutate(pr);
    assert.equal(run.isExempt(pr, repository).exempt, false);
  }
});

function harness(permission, action = 'reopened') {
  const labels = [];
  const pr = { ...maintenancePr(), user: { login: 'external-contributor', type: 'User' } };
  const context = { repo: { owner: 'himmelblau-idm', repo: 'himmelblau' },
    actor: 'reviewer', payload: { action, pull_request: pr } };
  const github = {
    rest: {
      repos: { getCollaboratorPermissionLevel: async () => ({ data: { permission } }) },
      issues: {
        listComments: () => {},
        addLabels: async (args) => { labels.push(args); },
      },
      pulls: { get: async () => { throw new Error('ordinary checks reached'); } },
      users: { getByUsername: async () => ({ data: {} }) },
    },
    paginate: async () => [],
  };
  return { github, context, core: { info: () => {}, setFailed: assert.fail }, labels };
}

test('a verified maintainer reopen persists the existing exemption label', async () => {
  for (const permission of ['admin', 'maintain', 'write']) {
    const fixture = harness(permission);
    await run(fixture);
    assert.deepEqual(fixture.labels[0].labels, ['slop-guard-exempt']);
  }
});

test('an external reopen still runs ordinary checks', async () => {
  const fixture = harness('read');
  await assert.rejects(run(fixture), /ordinary checks reached/);
  assert.equal(fixture.labels.length, 0);
});

test('opening a PR does not inherit the event actor maintainer exemption', async () => {
  const fixture = harness('admin', 'opened');
  await assert.rejects(run(fixture), /ordinary checks reached/);
  assert.equal(fixture.labels.length, 0);
});

test('scheduled screening exempts the same trusted maintenance PR', async () => {
  const workflow = fs.readFileSync(path.join(__dirname, '../workflows/pr-slop-guard.yml'), 'utf8');
  assert.match(workflow, /ref: main\n\s+persist-credentials: false/);
  const source = workflow.slice(workflow.indexOf('            const OWNER ='))
    .split('\n').map((line) => line.slice(12)).join('\n');
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const messages = [];
  const fixture = harness('read');
  fixture.github.paginate = async () => [maintenancePr()];
  fixture.core.info = (message) => messages.push(message);
  await new AsyncFunction('github', 'context', 'core', source)(
    fixture.github, fixture.context, fixture.core,
  );
  assert.ok(messages.some((message) => message.includes('repository stable-maintenance automation')));
  assert.ok(messages.some((message) => message.includes('Closed 0 PR(s). Failed 0 PR(s).')));
});
