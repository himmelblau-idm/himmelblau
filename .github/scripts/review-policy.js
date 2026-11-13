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

// These rules come from trusted main, never the candidate PR. Test both
// names of a rename so moving code cannot shed its review requirement.
const SENSITIVE_DIRS = [
  '.github', 'src/pam', 'src/nss', 'src/daemon', 'src/common', 'src/idmap',
  'src/broker', 'src/broker-client', 'src/sso', 'src/cli', 'src/policies',
  'src/sshd-config', 'platform/systemd', 'nix/modules', 'src/overrides',
  'supply-chain',
];
const SENSITIVE_FILES = new Set([
  'scripts/gen_authselect.py', 'scripts/gen_servicefiles.py',
  'scripts/obs_update.py', 'scripts/backport.py', 'scripts/fix-bugs.py',
  'scripts/dependabot_automerge_check.sh', 'scripts/dependabot_rollup.py',
  'scripts/cargo_vet_review.py', 'scripts/cargo-patch-config.toml',
]);
const SECURITY_DEP = /\b(?:libhimmelblau|identity_dbus_broker|broker-client|okta(?:-auth-rs)?|openidconnect|oauth2|libkrimes|kanidm[\w-]*|crypto[\w-]*|rsa|rustls[\w-]*|openssl[\w-]*|ring|aws-lc[\w-]*|webpki[\w-]*|zeroize|secrecy|webauthn[\w-]*|sha2|authenticator|libwebauthn)\b/i;

function normalizeManifestDiffLine(line) {
  const trimmed = line.trim();
  if (/^(?:edition|features|default-features)\s*=/i.test(trimmed)) return trimmed;
  let normalized = trimmed;
  normalized = normalized.replace(/^version\s*=\s*"[^"]*"/, 'version = "VERSION"');
  // Only plain dependency version requirements (digit-led quoted values), not
  // packaging hooks or other manifest strings.
  normalized = normalized.replace(/^([\w.-]+)\s*=\s*"[0-9][^"]*"/, '$1 = "VERSION"');
  normalized = normalized.replace(/\bversion\s*=\s*"[^"]*"/g, 'version = "VERSION"');
  return normalized;
}

function versionBumpOnly(patch) {
  const removed = [], added = [];
  for (const line of patch.split('\n')) {
    if (!/^[+-](?![+-])/.test(line)) continue;
    const normalized = normalizeManifestDiffLine(line.slice(1));
    (line[0] === '+' ? added : removed).push(normalized);
  }
  return removed.length > 0 && JSON.stringify(removed) === JSON.stringify(added);
}

function sensitiveChanges(pr, files) {
  if (!Array.isArray(files) || !Number.isInteger(pr.changed_files)
      || files.length !== pr.changed_files) return ['Changed-file list is incomplete.'];
  const sensitive = [];
  for (const file of files) {
    const paths = [file.filename, file.previous_filename].filter(Boolean);
    if (!paths.length) return ['Changed-file metadata is incomplete.'];
    if (paths.some(p => SENSITIVE_DIRS.some(d => p === d || p.startsWith(`${d}/`))
        || SENSITIVE_FILES.has(p) || /^platform\/[^/]+\/(?:pam-config[^/]*|sshd_config)$/.test(p)
        || /(?:^|\/)build\.rs$/.test(p))) {
      sensitive.push(file.filename);
      continue;
    }
    const patch = file.patch;
    const changed = patch?.split('\n').filter(l => /^[+-](?![+-])/.test(l)).join('\n');
    const buildFile = paths.some(p => /(?:^|\/)(?:Cargo\.nix|flake\.lock|flake\.nix|sources\.nix|default\.nix|Makefile)$/.test(p)
        || p.startsWith('.cargo/'));
    // Build orchestration files need a human until a version-only allowlist
    // exists. Cargo manifests/locks keep the narrower rules below.
    if (buildFile) {
      sensitive.push(file.filename);
      continue;
    }
    if (paths.some(p => /(?:^|\/)(?:Cargo\.toml|Cargo\.lock)$/.test(p))) {
      if (!patch || SECURITY_DEP.test(patch)
          || (paths.some(p => /(?:^|\/)Cargo\.toml$/.test(p)) && !versionBumpOnly(patch))
          || /\b(?:git|path|registry|source|patch|replace|build|features|default-features)\s*[=:]/i.test(changed)
          || /(?:https?:\/\/|git\+|ExecStart|chmod|chown|setcap|rustc-workspace-wrapper)/i.test(changed)) {
        sensitive.push(file.filename);
      }
    }
  }
  return sensitive;
}

// Commands must be the entire comment, not quoted text or a substring of a
// conversation. Full SHAs ensure a new push invalidates every attestation.
function command(comment, sha) {
  if (comment.user?.type !== 'User') return null;
  const match = /^\/(confirm-tested|revoke-tested|sponsor-ai|revoke-sponsor) ([a-f0-9]{40})(?: (https:\/\/github\.com\/[^\s]+))?$/.exec((comment.body || '').trim());
  if (!match || match[2] !== sha || (match[3] && match[1] !== 'confirm-tested')) return null;
  return { action: match[1], evidence: match[3], comment };
}

function latestCommand(comments, permissions, sha, actions) {
  return comments.map(c => command(c, sha))
    .filter(c => c && permissions[c.comment.user.login] === true && actions.includes(c.action))
    .sort((a, b) => (Date.parse(a.comment.updated_at || a.comment.created_at) || 0)
      - (Date.parse(b.comment.updated_at || b.comment.created_at) || 0)
      || Number(a.comment.id) - Number(b.comment.id)).at(-1);
}

async function testingConfirmation({ github, owner, repo, pr, comments, permissions }) {
  const latest = latestCommand(comments, permissions, pr.head.sha, ['confirm-tested', 'revoke-tested']);
  if (latest?.action !== 'confirm-tested') return null;
  if (!latest.evidence) return { by: latest.comment.user.login, url: latest.comment.html_url };
  const url = new URL(latest.evidence);
  const match = /^\/([^/]+)\/([^/]+)\/(issues|pull)\/(\d+)$/.exec(url.pathname);
  const anchor = /^#issuecomment-(\d+)$/.exec(url.hash);
  if (!match || !anchor || url.search || url.origin !== 'https://github.com'
      || match[1].toLowerCase() !== owner.toLowerCase() || match[2].toLowerCase() !== repo.toLowerCase()) return null;
  const number = Number(match[4]);
  if (match[3] === 'pull' ? number !== pr.number : !await linkedIssue(github, owner, repo, pr, number)) return null;
  let evidence;
  try {
    ({ data: evidence } = await github.rest.issues.getComment({ owner, repo, comment_id: Number(anchor[1]) }));
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
  if (evidence.issue_url !== `https://api.github.com/repos/${owner}/${repo}/issues/${number}`
      || evidence.user?.type !== 'User' || !evidence.body?.trim()) return null;
  // The writer attests that the linked human comment reports successful
  // testing of this head and resolution of the bug; no prose classifier.
  return { by: latest.comment.user.login, url: latest.evidence, tester: evidence.user.login };
}

async function linkedIssue(github, owner, repo, pr, number) {
  const explicit = new RegExp(`https://github\\.com/${owner}/${repo}/issues/${number}(?![0-9])`, 'i');
  if (explicit.test(pr.body || '')) return true;
  let cursor = null;
  do {
    const result = await github.graphql(`query($owner:String!,$repo:String!,$number:Int!,$cursor:String) {
      repository(owner:$owner,name:$repo) { pullRequest(number:$number) {
        closingIssuesReferences(first:100,after:$cursor) {
          nodes { number repository { nameWithOwner } } pageInfo { hasNextPage endCursor }
        }
      } }
    }`, { owner, repo, number: pr.number, cursor });
    const connection = result.repository.pullRequest.closingIssuesReferences;
    if (connection.nodes.some(i => i.number === number
        && i.repository.nameWithOwner.toLowerCase() === `${owner}/${repo}`.toLowerCase())) return true;
    cursor = connection.pageInfo.hasNextPage ? connection.pageInfo.endCursor : null;
  } while (cursor);
  return false;
}

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
  if (provider !== 'coderabbit' && review.state === 'APPROVED') return provider;
  if (!['COMMENTED', 'APPROVED'].includes(review.state)) return null;
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

function evaluate({ pr, authorCanWrite, permissions, reviews, threads, checks, comments, files, tested = null }) {
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
    if (review.commit_id !== pr.head.sha) continue;
    const provider = AI.get(review.user.login);
    votes.delete(`ai:${provider}`);
    const clean = cleanBotReview(review, checks, comments, pr.head.sha);
    if (clean && review.user.login !== pr.user.login) votes.set(`ai:${clean}`, 'ai');
  }
  if (pr.user.login !== 'chatgpt-codex-connector[bot]' && cleanCodexComment(comments, reviews, pr.head.sha)) {
    votes.set('ai:codex', 'ai');
  }
  const humanCount = [...votes.values()].filter(v => v === 'human').length;
  const sponsorship = latestCommand(comments, permissions, pr.head.sha, ['sponsor-ai', 'revoke-sponsor']);
  const sponsoredBot = pr.user.type === 'Bot' && sponsorship?.action === 'sponsor-ai';
  const teamAuthor = authorCanWrite || sponsoredBot;
  const sensitive = sensitiveChanges(pr, files);
  if (sensitive.length && humanCount < 1) reasons.push(`Human approval required for sensitive changes: ${sensitive.join(', ')}.`);
  if (teamAuthor ? votes.size < 1 : votes.size < 2 || humanCount < 1) {
    reasons.push(teamAuthor ? 'Need one current human or AI approval.'
      : 'Need two distinct current reviewers, including a human with write access.');
  }
  // Incomplete API results block manual eligibility too, not just automation.
  if (!Array.isArray(files) || files.length !== pr.changed_files) reasons.push('Cannot verify all changed files.');
  const autoReasons = [];
  if (!teamAuthor) autoReasons.push('Outside-contributor PRs require manual merging by a writer.');
  if (sensitive.length) autoReasons.push('Sensitive changes require manual merging, even with human approval.');
  if (!tested) autoReasons.push('Waiting for a writer to confirm successful testing and bug resolution on this head.');
  return { eligible: reasons.length === 0, reasons, reviewers: [...votes.keys()], sensitive,
    teamAuthor, sponsoredBy: sponsoredBot ? sponsorship.comment.user.login : null,
    autoEligible: reasons.length === 0 && autoReasons.length === 0, autoReasons };
}

function ciReasons(headChecks, headStatuses, mergeChecks = [], mergeStatuses = []) {
  const reasons = [];
  const headLatest = latestBy(headChecks, c => `${c.app?.id}:${c.name}`);
  const mergeLatest = latestBy(mergeChecks, c => `${c.app?.id}:${c.name}`);
  const mandatory = [...headLatest, ...mergeLatest];
  for (const name of REQUIRED_CI) {
    if (!mandatory.some(c => c.name === name && c.app?.id === ACTIONS_APP
      && c.status === 'completed' && c.conclusion === 'success')) reasons.push(`Waiting for successful ${name}.`);
  }
  for (const latest of [headLatest, mergeLatest]) {
    for (const check of latest) {
      // The coordinator and its read-only wakeup are not CI. Counting the
      // running coordinator would prevent it ever reaching the merge call.
      if (check.app?.id === ACTIONS_APP
          && [CHECK, 'Evaluate main reviews', 'Review policy wakeup'].includes(check.name)) continue;
      if (check.status !== 'completed' || !['success', 'neutral', 'skipped'].includes(check.conclusion)) {
        reasons.push(`Check ${check.name} is ${check.conclusion || check.status}.`);
      }
    }
  }
  for (const statuses of [headStatuses, mergeStatuses]) {
    for (const status of latestBy(statuses, s => s.context)) {
      if (status.state !== 'success') reasons.push(`Status ${status.context} is ${status.state}.`);
    }
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
      for (const comment of comments) {
        if (command(comment, sha)) await canWrite(comment.user.login);
      }
      const files = await github.paginate(github.rest.pulls.listFiles, { ...args, pull_number: pr.number });
      const tested = await testingConfirmation({ github, owner, repo, pr, comments, permissions });
      const checks = await github.paginate(github.rest.checks.listForRef, { ...args, ref: sha, filter: 'all' });
      const statuses = await github.paginate(github.rest.repos.listCommitStatusesForRef, { ...args, ref: sha });
      const policy = evaluate({ pr, authorCanWrite, permissions, reviews, threads, files, tested,
        checks: latestBy(checks, c => `${c.app?.id}:${c.name}`), comments });
      let mergeChecks = [];
      let mergeStatuses = [];
      if (pr.merge_commit_sha && pr.merge_commit_sha !== sha) {
        mergeChecks = await github.paginate(github.rest.checks.listForRef, { ...args, ref: pr.merge_commit_sha, filter: 'all' });
        mergeStatuses = await github.paginate(github.rest.repos.listCommitStatusesForRef, { ...args, ref: pr.merge_commit_sha });
      }
      // PR workflows may report on the synthetic merge SHA instead of head.
      // Mandatory names may succeed on either ref; other checks and statuses
      // are evaluated per ref so one cannot hide a failure on the other.
      const ci = ciReasons(checks, statuses, mergeChecks, mergeStatuses);
      const fresh = (await github.rest.pulls.get({ owner, repo, pull_number: pr.number })).data;
      if (fresh.head.sha !== sha || fresh.base.ref !== 'main' || fresh.base.sha !== pr.base.sha
          || fresh.state !== 'open' || fresh.draft !== pr.draft) {
        core.info(`#${pr.number}: PR changed during evaluation; retry on next event.`);
        continue;
      }
      const description = [...policy.reasons, ...ci, ...policy.autoReasons];
      const existing = checks.find(c => c.name === CHECK && c.app?.id === ACTIONS_APP
        && c.external_id === `main-review-policy:${pr.number}`);
      const output = {
        title: policy.eligible ? 'Review requirements satisfied' : 'Waiting for reviews or discussion resolution',
        summary: [`Author has write access: ${authorCanWrite}.`,
          `AI companion sponsor: ${policy.sponsoredBy || 'none'}.`,
          `Sensitive paths: ${(policy.sensitive || []).join(', ') || 'none'}.`,
          `Testing confirmed by: ${tested?.by || 'nobody'}${tested?.url ? ` (${tested.url})` : ''}.`,
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
      if (merge && policy.autoEligible && ci.length === 0 && fresh.mergeable === true
          && fresh.mergeable_state === 'clean') {
        // Re-read reviews, threads, permissions and attestations at the merge
        // boundary. GitHub's SHA lease and native protections remain the final
        // guard; reads and a merge cannot be made atomic through this API.
        const finalReviews = await github.paginate(github.rest.pulls.listReviews, { ...args, pull_number: pr.number });
        const finalComments = await github.paginate(github.rest.issues.listComments, { ...args, issue_number: pr.number });
        const finalThreads = await reviewThreads(github, owner, repo, pr.number);
        for (const login of Object.keys(permissions)) delete permissions[login];
        const finalAuthorCanWrite = pr.user.type === 'User' && await canWrite(pr.user.login);
        for (const review of finalReviews) {
          if (review.user.type === 'User') await canWrite(review.user.login);
        }
        for (const comment of finalComments) {
          if (command(comment, sha)) await canWrite(comment.user.login);
        }
        const finalTested = await testingConfirmation({ github, owner, repo, pr, comments: finalComments, permissions });
        const finalChecks = await github.paginate(github.rest.checks.listForRef, { ...args, ref: sha, filter: 'all' });
        const finalStatuses = await github.paginate(github.rest.repos.listCommitStatusesForRef, { ...args, ref: sha });
        let finalMergeChecks = [];
        let finalMergeStatuses = [];
        if (pr.merge_commit_sha && pr.merge_commit_sha !== sha) {
          finalMergeChecks = await github.paginate(github.rest.checks.listForRef, { ...args, ref: pr.merge_commit_sha, filter: 'all' });
          finalMergeStatuses = await github.paginate(github.rest.repos.listCommitStatusesForRef, { ...args, ref: pr.merge_commit_sha });
        }
        const finalCI = ciReasons(finalChecks, finalStatuses, finalMergeChecks, finalMergeStatuses);
        const finalPolicy = evaluate({ pr, authorCanWrite: finalAuthorCanWrite, permissions,
          reviews: finalReviews, comments: finalComments, threads: finalThreads, files, tested: finalTested,
          checks: latestBy(finalChecks, c => `${c.app?.id}:${c.name}`) });
        if (!finalPolicy.autoEligible || finalCI.length) {
          await github.rest.checks.update({ ...check, check_run_id: checkId,
            conclusion: finalPolicy.eligible ? 'success' : 'failure',
            output: { title: 'Automatic merge deferred after revalidation',
              summary: [...finalPolicy.reasons, ...finalPolicy.autoReasons, ...finalCI].join('\n\n') } });
          continue;
        }
        const finalPR = (await github.rest.pulls.get({ owner, repo, pull_number: pr.number })).data;
        if (finalPR.head.sha !== sha || finalPR.base.ref !== 'main' || finalPR.base.sha !== pr.base.sha
            || finalPR.state !== 'open' || finalPR.draft || finalPR.mergeable !== true
            || finalPR.mergeable_state !== 'clean') continue;
        const result = await github.rest.pulls.merge({ owner, repo, pull_number: pr.number,
          merge_method: 'squash', sha });
        core.info(`#${pr.number}: ${result.data.message}`);
      }
    } catch (error) {
      errors++;
      core.error(`#${summary.number}: ${error.message}`);
      // Revoke an earlier success if a later evaluation cannot complete.
      const headSha = pr?.head?.sha || summary.head?.sha;
      const baseRef = pr?.base?.ref || summary.base?.ref;
      if (headSha && baseRef === 'main') {
        const failure = { owner, repo, name: CHECK, status: 'completed', conclusion: 'failure',
          output: { title: 'Policy evaluation failed', summary: 'Inspect the Main review policy workflow logs. No automatic merge was attempted after this error.' } };
        if (checkId) await github.rest.checks.update({ ...failure, check_run_id: checkId });
        else await github.rest.checks.create({ ...failure, head_sha: headSha, external_id: `main-review-policy:${summary.number}` });
      }
    }
  }
  if (errors) core.setFailed(`${errors} PR policy evaluation(s) failed.`);
}

module.exports = { run, evaluate, ciReasons, cleanBotReview, sensitiveChanges,
  testingConfirmation, command, REQUIRED_CI, CHECK };

