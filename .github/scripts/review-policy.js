'use strict';

// This module runs only from trusted main, never from a PR checkout.
const CHECK = 'Review policy';
const ACTIONS_APP = 15368;
const REQUIRED_CI = ['Build', 'Test', 'Clippy', 'Vet Dependencies'];
const AI = new Map([
  ['coderabbitai[bot]', 'coderabbit'],
  ['copilot-pull-request-reviewer[bot]', 'copilot'],
  ['chatgpt-codex-connector[bot]', 'codex'],
]);
const DELEGATED = /^<!-- review-policy:ai:(coderabbit|copilot|codex) -->\s*$/m;

function latestBy(items, key) {
  const result = new Map();
  for (const item of [...items].sort((a, b) => Number(a.id) - Number(b.id))) {
    result.set(key(item), item);
  }
  return [...result.values()];
}

function delegated(review) {
  return DELEGATED.exec(review.body || '')?.[1]
    // Older reviews in this repository used this explicit disclosure.
    || (/contributing this review as Codex/i.test(review.body || '') ? 'codex' : null);
}

function cleanBotReview(review, checks, comments, sha) {
  const provider = review.user?.type === 'Bot' && AI.get(review.user.login);
  if (!provider || review.commit_id !== sha) return null;
  if (review.state === 'APPROVED') return provider;
  if (review.state !== 'COMMENTED') return null;
  const body = review.body || '';
  if (provider === 'coderabbit') {
    // The app's success check means publication completed, not that there
    // were no findings. Also require its SHA-bound clean review summary.
    const completed = checks.some(c => c.name === 'CodeRabbit'
      && c.app?.id === 347564 && c.app?.slug === 'coderabbitai'
      && c.status === 'completed' && c.conclusion === 'success');
    const summaries = latestBy(comments.filter(c => c.user?.login === 'coderabbitai[bot]'
      && c.user?.type === 'Bot' && (c.body || '').includes('<!-- recent_review_status_start -->')),
    () => 'summary');
    const clean = summaries.some(c => {
      const text = c.body || '';
      return text.includes(`<!-- change_assessment_commit:"${sha}" -->`)
        && /<!-- recent_review_status_start -->\s*No actionable comments were generated in the recent review\.\s*<!-- recent_review_status_end -->/.test(text)
        && !/Failed pre-merge checks:/.test(text);
    });
    return completed && clean && !/Failed pre-merge checks:|Actionable comments posted:\s*[1-9]/.test(body) ? provider : null;
  }
  if (provider === 'copilot') {
    // "No open issues" alone also appears under "Needs a closer look".
    return /^<!-- ccr-overview-v2 -->\s*### [^\n]*Ready to approve\s*$/m.test(body)
      && /\*\*No open issues\*\*/.test(body) ? provider : null;
  }
  // A formal Codex review is commit-bound. Reactions on a PR are not and
  // cannot prove that Codex reviewed its current head.
  return /^###?\s*(?:🤖\s*)?Codex Review:\s*(?:Didn't find any major issues\.|No findings\.)/m.test(body)
    ? provider : null;
}

function cleanCodexComment(comments, reviews, sha) {
  const login = 'chatgpt-codex-connector[bot]';
  const latest = latestBy(comments.filter(c => c.user?.type === 'Bot' && c.user.login === login), () => login)[0];
  if (!latest) return false;
  const body = latest.body || '';
  const reviewed = /Reviewed commit:\s*`([a-f0-9]{10,40})`/.exec(body)?.[1];
  if (!reviewed || !sha.startsWith(reviewed)
      || !/^(?:#{1,3}\s*)?(?:[💡🤖]+\s*)?Codex Review:\s*Didn't find any major issues\./mu.test(body)) return false;
  // A newer submitted review can supersede this comment with findings.
  return !reviews.some(r => r.user?.type === 'Bot' && r.user.login === login
    && r.state !== 'PENDING' && r.commit_id === sha
    && Date.parse(r.submitted_at) > Date.parse(latest.updated_at || latest.created_at));
}

function evaluate({ pr, authorCanWrite, permissions, reviews, threads, checks, comments }) {
  const reasons = [];
  if (pr.base.ref !== 'main') return { eligible: false, reasons: ['Only main is eligible.'] };
  if (pr.state !== 'open' || pr.draft) reasons.push('PR must be open and ready for review.');
  if (threads.some(t => !t.isResolved)) reasons.push('Unresolved review threads remain (including outdated threads).');
  // PENDING reviews, comments, and replies do not supersede a submitted
  // approval or changes request. A dismissal does supersede it.
  const decisions = latestBy(reviews.filter(r => ['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'].includes(r.state)), r => r.user.login);
  if (decisions.some(r => r.state === 'CHANGES_REQUESTED'
      && (permissions[r.user.login] || (r.user.type === 'Bot' && AI.has(r.user.login))))) {
    reasons.push('An authorized reviewer still requests changes.');
  }
  const votes = new Map();
  for (const review of decisions) {
    if (review.state !== 'APPROVED' || review.commit_id !== pr.head.sha
        || review.user.login === pr.user.login) continue;
    const provider = review.user.type === 'Bot' && AI.get(review.user.login);
    if (provider) votes.set(`ai:${provider}`, 'ai');
    else if (review.user.type === 'User' && permissions[review.user.login]) {
      const ai = delegated(review);
      votes.set(ai ? `ai:${ai}` : `human:${review.user.login}`, ai ? 'ai' : 'human');
    }
  }
  // Use the most recent submitted review by each bot, not an earlier clean
  // assessment superseded by findings on the same head.
  const latestBotReviews = latestBy(reviews.filter(r => r.state !== 'PENDING'
    && r.user.type === 'Bot' && AI.has(r.user.login)), r => r.user.login);
  for (const review of latestBotReviews) {
    const provider = AI.get(review.user.login);
    votes.delete(`ai:${provider}`);
    const clean = cleanBotReview(review, checks, comments, pr.head.sha);
    if (clean && review.user.login !== pr.user.login) votes.set(`ai:${clean}`, 'ai');
  }
  if (pr.user.login !== 'chatgpt-codex-connector[bot]' && cleanCodexComment(comments, reviews, pr.head.sha)) {
    votes.set('ai:codex', 'ai');
  }
  const humanCount = [...votes.values()].filter(v => v === 'human').length;
  if (authorCanWrite ? votes.size < 1 : votes.size < 2 || humanCount < 1) {
    reasons.push(authorCanWrite ? 'Need one current human or AI approval.'
      : 'Need two distinct current reviewers, including a human with write access.');
  }
  return { eligible: reasons.length === 0, reasons, reviewers: [...votes.keys()] };
}

function ciReasons(checks, statuses) {
  const reasons = [];
  const latest = latestBy(checks, c => `${c.app?.id}:${c.name}`);
  for (const name of REQUIRED_CI) {
    if (!latest.some(c => c.name === name && c.app?.id === ACTIONS_APP
      && c.status === 'completed' && c.conclusion === 'success')) reasons.push(`Waiting for successful ${name}.`);
  }
  for (const check of latest) {
    // The coordinator and its read-only wakeup are not CI. Counting the
    // running coordinator would prevent it ever reaching the merge call.
    if (check.app?.id === ACTIONS_APP
        && [CHECK, 'Evaluate main reviews', 'Review policy wakeup'].includes(check.name)) continue;
    if (check.status !== 'completed' || !['success', 'neutral', 'skipped'].includes(check.conclusion)) {
      reasons.push(`Check ${check.name} is ${check.conclusion || check.status}.`);
    }
  }
  for (const status of latestBy(statuses, s => s.context)) {
    if (status.state !== 'success') reasons.push(`Status ${status.context} is ${status.state}.`);
  }
  return reasons;
}

async function reviewThreads(github, owner, repo, number) {
  const threads = [];
  let cursor = null;
  do {
    const result = await github.graphql(`query($owner:String!,$repo:String!,$number:Int!,$cursor:String) {
      repository(owner:$owner,name:$repo) { pullRequest(number:$number) {
        reviewThreads(first:100,after:$cursor) { nodes { isResolved } pageInfo { hasNextPage endCursor } }
      } }
    }`, { owner, repo, number, cursor });
    const connection = result.repository.pullRequest.reviewThreads;
    threads.push(...connection.nodes);
    cursor = connection.pageInfo.hasNextPage ? connection.pageInfo.endCursor : null;
  } while (cursor);
  return threads;
}

async function run({ github, context, core, merge = false }) {
  const { owner, repo } = context.repo;
  // Both the trigger and this API filter enforce the main-only scope.
  const prs = await github.paginate(github.rest.pulls.list, { owner, repo, state: 'open', base: 'main', per_page: 100 });
  let errors = 0;
  for (const summary of prs) {
    let pr, checkId;
    try {
      pr = (await github.rest.pulls.get({ owner, repo, pull_number: summary.number })).data;
      if (pr.base.ref !== 'main' || pr.state !== 'open') continue;
      const sha = pr.head.sha;
      const args = { owner, repo, per_page: 100 };
      const permissions = {};
      async function canWrite(login) {
        if (Object.hasOwn(permissions, login)) return permissions[login];
        try {
          const { data } = await github.rest.repos.getCollaboratorPermissionLevel({ owner, repo, username: login });
          return (permissions[login] = data.user?.permissions?.push === true
            || ['write', 'maintain', 'admin'].includes(data.permission));
        } catch (error) {
          if (error.status === 404) return (permissions[login] = false);
          throw error;
        }
      }
      const authorCanWrite = pr.user.type === 'User' && await canWrite(pr.user.login);
      const reviews = await github.paginate(github.rest.pulls.listReviews, { ...args, pull_number: pr.number });
      for (const review of reviews) {
        if (review.user.type === 'User') await canWrite(review.user.login);
      }
      const threads = await reviewThreads(github, owner, repo, pr.number);
      const comments = await github.paginate(github.rest.issues.listComments, { ...args, issue_number: pr.number });
      const checks = await github.paginate(github.rest.checks.listForRef, { ...args, ref: sha, filter: 'all' });
      const statuses = await github.paginate(github.rest.repos.listCommitStatusesForRef, { ...args, ref: sha });
      const policy = evaluate({ pr, authorCanWrite, permissions, reviews, threads,
        checks: latestBy(checks, c => `${c.app?.id}:${c.name}`), comments });
      const ci = ciReasons(checks, statuses);
      // PR workflows may report on the synthetic merge SHA instead of head.
      // If present, failures/pending checks on that SHA also prevent merging.
      if (pr.merge_commit_sha && pr.merge_commit_sha !== sha) {
        const mergeChecks = await github.paginate(github.rest.checks.listForRef, { ...args, ref: pr.merge_commit_sha, filter: 'all' });
        const mergeStatuses = await github.paginate(github.rest.repos.listCommitStatusesForRef, { ...args, ref: pr.merge_commit_sha });
        // Mandatory names may be satisfied on either current head or current
        // synthetic merge; do not require duplicate CI executions.
        const combined = ciReasons([...checks, ...mergeChecks], [...statuses, ...mergeStatuses]);
        ci.splice(0, ci.length, ...combined);
      }
      const fresh = (await github.rest.pulls.get({ owner, repo, pull_number: pr.number })).data;
      if (fresh.head.sha !== sha || fresh.base.ref !== 'main' || fresh.base.sha !== pr.base.sha
          || fresh.state !== 'open' || fresh.draft !== pr.draft) {
        core.info(`#${pr.number}: PR changed during evaluation; retry on next event.`);
        continue;
      }
      const description = [...policy.reasons, ...ci];
      const existing = checks.find(c => c.name === CHECK && c.app?.id === ACTIONS_APP
        && c.external_id === `main-review-policy:${pr.number}`);
      const output = {
        title: policy.eligible ? 'Review requirements satisfied' : 'Waiting for reviews or discussion resolution',
        summary: [`Author has write access: ${authorCanWrite}.`,
          `Current reviewers: ${(policy.reviewers || []).join(', ') || 'none'}.`,
          ...description, merge ? 'Automatic squash merge enabled.' : 'Report only; automatic merging disabled.'].join('\n\n'),
      };
      // This check represents reviews only. Native required CI remains an
      // independent server-side gate, and the coordinator also inspects CI.
      const check = { owner, repo, name: CHECK, status: 'completed',
        conclusion: policy.eligible ? 'success' : 'failure', output };
      if (existing) {
        checkId = existing.id;
        await github.rest.checks.update({ ...check, check_run_id: checkId });
      } else {
        const created = await github.rest.checks.create({ ...check, head_sha: sha, external_id: `main-review-policy:${pr.number}` });
        checkId = created.data.id;
      }
      core.info(`#${pr.number}: ${description.join(' ') || 'Ready to merge.'}`);
      // GitHub enforces protections again at merge time; never use an admin
      // bypass. Unknown/blocked/behind states wait instead of forcing merge.
      if (merge && policy.eligible && ci.length === 0 && fresh.mergeable === true
          && fresh.mergeable_state === 'clean') {
        const result = await github.rest.pulls.merge({ owner, repo, pull_number: pr.number,
          merge_method: 'squash', sha });
        core.info(`#${pr.number}: ${result.data.message}`);
      }
    } catch (error) {
      errors++;
      core.error(`#${summary.number}: ${error.message}`);
      // Revoke an earlier success if a later evaluation cannot complete.
      if (pr?.head?.sha && pr.base.ref === 'main') {
        const failure = { owner, repo, name: CHECK, status: 'completed', conclusion: 'failure',
          output: { title: 'Policy evaluation failed', summary: 'Inspect the Main review policy workflow logs. No automatic merge was attempted after this error.' } };
        if (checkId) await github.rest.checks.update({ ...failure, check_run_id: checkId });
        else await github.rest.checks.create({ ...failure, head_sha: pr.head.sha, external_id: `main-review-policy:${summary.number}` });
      }
    }
  }
  if (errors) core.setFailed(`${errors} PR policy evaluation(s) failed.`);
}

module.exports = { run, evaluate, ciReasons, cleanBotReview, REQUIRED_CI, CHECK };
