'use strict';

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

const MAX_FAILURES = 4;
const ACCOUNT_AGE_DAYS = 30;
const MAX_COMMITS = 10;
const MAX_CHANGED_LINES = 5000;
const MAX_DESCRIPTION_LENGTH = 2500;
const MAX_EMOJI_COUNT = 2;
const MAX_ADDED_COMMENTS = 15;

const BLOCKED_TERMS = ['PINEAPPLE'];

const BLOCKED_PATHS = [
  'README.md',
  'SECURITY.md',
  'LICENSE',
  'CODE_OF_CONDUCT.md',
  'CLAUDE.md',
  'CONTRIBUTOR_POLICY.md',
];

const TEMPLATE_SECTIONS = [
  '## Summary',
  '## What Changed',
  '## Testing',
  '## Automated Checks',
  '## System Integration Impact',
  '## Checklist',
];

const COMMENT_PREFIXES = {
  rs: ['//', '/*', '*'],
  py: ['#'],
  sh: ['#'],
  toml: ['#'],
  yml: ['#'],
  yaml: ['#'],
  js: ['//', '/*', '*'],
  xml: ['<!--'],
  c: ['//', '/*', '*'],
  h: ['//', '/*', '*'],
  te: ['#'],
  fc: ['#'],
  if: ['#'],
};

const DEPENDABOT_LOGINS = new Set(['dependabot[bot]', 'dependabot-preview[bot]']);
const INTERNAL_ASSOCIATIONS = new Set(['OWNER', 'MEMBER', 'COLLABORATOR']);
const EXEMPT_LABEL = 'slop-guard-exempt';

const COMMENT_SENTINEL_START = '<!-- slop-guard-result:start -->';
const COMMENT_SENTINEL_END = '<!-- slop-guard-result:end -->';

const CONTRIBUTOR_POLICY_URL =
  'https://github.com/himmelblau-idm/himmelblau/blob/main/CONTRIBUTOR_POLICY.md';
const MATRIX_URL = 'https://matrix.to/#/#himmelblau:matrix.org';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stripHtmlComments(text) {
  return text.replace(/<!--[\s\S]*?-->/g, '');
}

function getFileExtension(filename) {
  const parts = filename.split('.');
  return parts.length > 1 ? parts[parts.length - 1] : '';
}

// ---------------------------------------------------------------------------
// Exemption check
// ---------------------------------------------------------------------------

function isExempt(pr) {
  const login = pr.user?.login || '';

  if (DEPENDABOT_LOGINS.has(login)) {
    return { exempt: true, reason: `author ${login} is dependabot` };
  }

  const association = (pr.author_association || 'UNKNOWN').trim().toUpperCase();
  if (INTERNAL_ASSOCIATIONS.has(association)) {
    return { exempt: true, reason: `author ${login} is ${association}` };
  }

  if (pr.draft) {
    return { exempt: true, reason: 'PR is a draft' };
  }

  const hasExemptLabel = (pr.labels || []).some(
    (l) => l && l.name && l.name.trim().toLowerCase() === EXEMPT_LABEL.toLowerCase()
  );
  if (hasExemptLabel) {
    return { exempt: true, reason: `has '${EXEMPT_LABEL}' label` };
  }

  return { exempt: false, reason: null };
}

// ---------------------------------------------------------------------------
// Description checks
// ---------------------------------------------------------------------------

function checkHoneypot(prData) {
  const body = prData.body || '';
  const visibleText = stripHtmlComments(body);

  for (const term of BLOCKED_TERMS) {
    if (visibleText.toUpperCase().includes(term.toUpperCase())) {
      return {
        name: 'honeypot',
        passed: false,
        message: `Description contains blocked term "${term}".`,
      };
    }
  }

  return { name: 'honeypot', passed: true, message: 'No blocked terms found.' };
}

function checkTemplateStructure(prData) {
  const body = (prData.body || '').trim();

  if (!body) {
    return {
      name: 'template-structure',
      passed: false,
      message: 'PR description is empty.',
    };
  }

  const foundSections = TEMPLATE_SECTIONS.filter((s) => body.includes(s));

  if (foundSections.length === 0) {
    return {
      name: 'template-structure',
      passed: false,
      message: `PR description contains none of the expected template sections (${TEMPLATE_SECTIONS.join(', ')}).`,
    };
  }

  // Check if the description is the unfilled template boilerplate.
  // Strip HTML comments and whitespace, check if only template headings and
  // placeholder text remain.
  const stripped = stripHtmlComments(body)
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .join('\n');

  // If after stripping the description is essentially just the section headers
  // plus the stock placeholder lines, treat as unfilled.
  const stockLines = [
    'Fixes #',
    '- **Distro(s) tested:**',
    '- **Steps performed:**',
    '- **Results observed:**',
    '- [ ] I ran `make test` (or explained why not)',
    '- [ ] I ran the distro package build target (or explained why not)',
    '- [ ] I ran `make test-selinux` (if applicable)',
    '- [ ] I manually tested this change on a test VM',
    '- [ ] PR scope is focused and linked to an issue/enhancement/discussion',
  ];
  const allKnownLines = [...TEMPLATE_SECTIONS, ...stockLines];
  const nonTemplateLine = stripped
    .split('\n')
    .find((line) => !allKnownLines.some((known) => line === known));

  if (!nonTemplateLine) {
    return {
      name: 'template-structure',
      passed: false,
      message: 'PR description appears to be the unfilled template boilerplate.',
    };
  }

  return {
    name: 'template-structure',
    passed: true,
    message: `Found ${foundSections.length}/${TEMPLATE_SECTIONS.length} template sections.`,
  };
}

function checkDescriptionLength(prData) {
  const body = prData.body || '';
  const visible = stripHtmlComments(body);
  const length = visible.length;

  if (length > MAX_DESCRIPTION_LENGTH) {
    return {
      name: 'description-length',
      passed: false,
      message: `Description is ${length} characters (max: ${MAX_DESCRIPTION_LENGTH}).`,
    };
  }

  return {
    name: 'description-length',
    passed: true,
    message: `Description is ${length} characters.`,
  };
}

function checkEmojiCount(prData) {
  const body = prData.body || '';

  // Count Unicode emojis (broad range).
  const unicodeEmojis = body.match(
    /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{FE00}-\u{FE0F}\u{1F900}-\u{1F9FF}\u{1FA00}-\u{1FA6F}\u{1FA70}-\u{1FAFF}\u{200D}\u{20E3}]/gu
  ) || [];

  // Count :shortcode: style emojis (e.g., :rocket:, :warning:).
  const shortcodeEmojis = body.match(/:[a-z0-9_+-]+:/gi) || [];

  const totalEmojis = unicodeEmojis.length + shortcodeEmojis.length;

  if (totalEmojis > MAX_EMOJI_COUNT) {
    return {
      name: 'emoji-count',
      passed: false,
      message: `Description contains ${totalEmojis} emojis (max: ${MAX_EMOJI_COUNT}).`,
    };
  }

  return {
    name: 'emoji-count',
    passed: true,
    message: `Description contains ${totalEmojis} emojis.`,
  };
}

// ---------------------------------------------------------------------------
// User checks
// ---------------------------------------------------------------------------

function checkAccountAge(_prData, userData) {
  const createdAt = new Date(userData.created_at);
  const now = new Date();
  const ageDays = (now - createdAt) / (1000 * 60 * 60 * 24);

  if (ageDays < ACCOUNT_AGE_DAYS) {
    return {
      name: 'account-age',
      passed: false,
      message: `Account is ${Math.floor(ageDays)} days old (min: ${ACCOUNT_AGE_DAYS}).`,
    };
  }

  return {
    name: 'account-age',
    passed: true,
    message: `Account is ${Math.floor(ageDays)} days old.`,
  };
}

function checkSpamUsername(prData) {
  const login = prData.user?.login || '';
  const patterns = [
    { regex: /^\d+$/, desc: 'username is all digits' },
    { regex: /\d{4,}/, desc: 'username contains 4+ consecutive digits' },
    { regex: /(?:^|-)ai(?:-|$)/i, desc: 'username contains "ai" segment' },
  ];

  for (const { regex, desc } of patterns) {
    if (regex.test(login)) {
      return {
        name: 'spam-username',
        passed: false,
        message: `Username "${login}" matches spam pattern: ${desc}.`,
      };
    }
  }

  return {
    name: 'spam-username',
    passed: true,
    message: `Username "${login}" does not match spam patterns.`,
  };
}

// ---------------------------------------------------------------------------
// Commit / diff checks
// ---------------------------------------------------------------------------

function checkCommitAuthorMatch(prData, commits) {
  const prAuthor = prData.user?.login || '';
  const mismatched = [];

  for (const commit of commits) {
    const commitAuthor = commit.author?.login || '';
    if (commitAuthor && commitAuthor !== prAuthor) {
      mismatched.push(`${commit.sha.substring(0, 7)} by ${commitAuthor}`);
    }
  }

  if (mismatched.length > 0) {
    return {
      name: 'commit-author-match',
      passed: false,
      message: `${mismatched.length} commit(s) authored by someone other than PR opener: ${mismatched.slice(0, 3).join(', ')}${mismatched.length > 3 ? '...' : ''}.`,
    };
  }

  return {
    name: 'commit-author-match',
    passed: true,
    message: 'All commits authored by PR opener.',
  };
}

function checkExcessiveCommits(prData) {
  const commitCount = prData.commits || 0;

  if (commitCount > MAX_COMMITS) {
    return {
      name: 'excessive-commits',
      passed: false,
      message: `PR has ${commitCount} commits (max: ${MAX_COMMITS}).`,
    };
  }

  return {
    name: 'excessive-commits',
    passed: true,
    message: `PR has ${commitCount} commits.`,
  };
}

function checkExcessiveChangedLines(prData) {
  const changedLines = (prData.additions || 0) + (prData.deletions || 0);

  if (changedLines > MAX_CHANGED_LINES) {
    return {
      name: 'excessive-changed-lines',
      passed: false,
      message: `PR changes ${changedLines} lines (max: ${MAX_CHANGED_LINES}).`,
    };
  }

  return {
    name: 'excessive-changed-lines',
    passed: true,
    message: `PR changes ${changedLines} lines.`,
  };
}

// ---------------------------------------------------------------------------
// File checks
// ---------------------------------------------------------------------------

function checkBlockedPaths(_prData, files) {
  const touched = [];

  for (const file of files) {
    const filename = file.filename || '';
    // Only match root-level files (no directory separator).
    if (!filename.includes('/') && BLOCKED_PATHS.includes(filename)) {
      touched.push(filename);
    }
  }

  if (touched.length > 0) {
    return {
      name: 'blocked-paths',
      passed: false,
      message: `PR modifies protected files: ${touched.join(', ')}.`,
    };
  }

  return {
    name: 'blocked-paths',
    passed: true,
    message: 'No protected files modified.',
  };
}

function checkExcessiveComments(_prData, files) {
  let totalCommentLines = 0;

  for (const file of files) {
    const filename = file.filename || '';
    const ext = getFileExtension(filename);
    const prefixes = COMMENT_PREFIXES[ext];
    if (!prefixes || !file.patch) {
      continue;
    }

    const addedLines = file.patch
      .split('\n')
      .filter((line) => line.startsWith('+') && !line.startsWith('+++'));

    for (const line of addedLines) {
      const content = line.substring(1).trim();
      if (content.length === 0) {
        continue;
      }
      if (prefixes.some((prefix) => content.startsWith(prefix))) {
        totalCommentLines++;
      }
    }
  }

  if (totalCommentLines > MAX_ADDED_COMMENTS) {
    return {
      name: 'excessive-comments',
      passed: false,
      message: `PR adds ${totalCommentLines} comment lines (max: ${MAX_ADDED_COMMENTS}).`,
    };
  }

  return {
    name: 'excessive-comments',
    passed: true,
    message: `PR adds ${totalCommentLines} comment lines.`,
  };
}

// ---------------------------------------------------------------------------
// Response formatting
// ---------------------------------------------------------------------------

function formatInfoComment(failures) {
  const lines = [
    COMMENT_SENTINEL_START,
    `Thanks for your contribution! A few items were flagged by our automated screening:`,
    '',
  ];

  for (const f of failures) {
    lines.push(`- :warning: **${f.name}**: ${f.message}`);
  }

  lines.push('');
  lines.push(
    `No action is required to keep this PR open, but please review these items. See our [contributor policy](${CONTRIBUTOR_POLICY_URL}) for guidance.`
  );
  lines.push(COMMENT_SENTINEL_END);

  return lines.join('\n');
}

function formatCloseComment(failures, totalChecks, author) {
  const lines = [
    COMMENT_SENTINEL_START,
    `Hi @${author},`,
    '',
    'Thank you for taking the time to contribute to Himmelblau - we appreciate your effort.',
    '',
    `This PR was automatically closed because it triggered multiple signals in our contributor screening (${failures.length} of ${totalChecks} checks failed):`,
    '',
  ];

  for (const f of failures) {
    lines.push(`- :x: **${f.name}**: ${f.message}`);
  }

  lines.push('');
  lines.push(
    `This is a metric-based review and does not determine whether your PR is AI-generated. Please review the contributor policy before resubmitting: ${CONTRIBUTOR_POLICY_URL}`
  );
  lines.push('');
  lines.push(
    `To discuss this decision or request a reopen, reach out in the Himmelblau Matrix channel: ${MATRIX_URL}`
  );
  lines.push('');
  lines.push('After discussion with the team, this PR may be reopened. :heart:');
  lines.push(COMMENT_SENTINEL_END);

  return lines.join('\n');
}

function formatJobSummary(results) {
  const lines = [
    '## Slop Guard Results',
    '',
    '| Check | Result | Details |',
    '|-------|--------|---------|',
  ];

  for (const r of results) {
    const icon = r.passed ? ':white_check_mark:' : ':x:';
    lines.push(`| ${r.name} | ${icon} | ${r.message} |`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

async function runAllChecks(_github, pr, userData, commits, files) {
  const results = [];

  // Description checks (no API calls needed, use pr data directly).
  results.push(checkHoneypot(pr));
  results.push(checkTemplateStructure(pr));
  results.push(checkDescriptionLength(pr));
  results.push(checkEmojiCount(pr));

  // User checks.
  results.push(checkAccountAge(pr, userData));
  results.push(checkSpamUsername(pr));

  // Commit/diff checks.
  results.push(checkCommitAuthorMatch(pr, commits));
  results.push(checkExcessiveCommits(pr));
  results.push(checkExcessiveChangedLines(pr));

  // File checks.
  results.push(checkBlockedPaths(pr, files));
  results.push(checkExcessiveComments(pr, files));

  return results;
}

// ---------------------------------------------------------------------------
// Comment management
// ---------------------------------------------------------------------------

async function findExistingComment(github, owner, repo, prNumber) {
  const comments = await github.paginate(github.rest.issues.listComments, {
    owner,
    repo,
    issue_number: prNumber,
    per_page: 100,
  });

  return comments.find(
    (c) => c.body && c.body.includes(COMMENT_SENTINEL_START)
  );
}

async function postOrUpdateComment(github, owner, repo, prNumber, body) {
  const existing = await findExistingComment(github, owner, repo, prNumber);

  if (existing) {
    await github.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existing.id,
      body,
    });
  } else {
    await github.rest.issues.createComment({
      owner,
      repo,
      issue_number: prNumber,
      body,
    });
  }
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

module.exports = async ({ github, context, core }) => {
  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const pr = context.payload.pull_request;

  if (!pr) {
    core.setFailed('Missing pull_request payload.');
    return;
  }

  const prNumber = pr.number;
  const author = pr.user?.login || 'unknown';

  core.info(`Evaluating PR #${prNumber} by ${author}.`);

  // --- Exemption check ---
  const exemption = isExempt(pr);
  if (exemption.exempt) {
    core.info(`PR #${prNumber}: skip (${exemption.reason}).`);
    return;
  }

  // --- Fetch data in parallel ---
  const [prDetails, commitsResponse, filesResponse, userData] = await Promise.all([
    github.rest.pulls.get({ owner, repo, pull_number: prNumber }),
    github.rest.pulls.listCommits({ owner, repo, pull_number: prNumber, per_page: 100 }),
    github.rest.pulls.listFiles({ owner, repo, pull_number: prNumber, per_page: 100 }),
    github.rest.users.getByUsername({ username: author }),
  ]);

  const prData = prDetails.data;
  const commits = commitsResponse.data;
  const files = filesResponse.data;
  const user = userData.data;

  // --- Run all checks ---
  const results = await runAllChecks(github, prData, user, commits, files);
  const failures = results.filter((r) => !r.passed);
  const failedCount = failures.length;

  // --- Write job summary ---
  await core.summary.addRaw(formatJobSummary(results)).write();

  core.info(`PR #${prNumber}: ${failedCount}/${results.length} checks failed.`);

  // --- Take action based on threshold ---
  if (failedCount === 0) {
    core.info(`PR #${prNumber}: all checks passed. No action needed.`);
    return;
  }

  if (failedCount < MAX_FAILURES) {
    core.info(`PR #${prNumber}: below threshold (${failedCount}/${MAX_FAILURES}). Posting informational comment.`);
    const body = formatInfoComment(failures);
    await postOrUpdateComment(github, owner, repo, prNumber, body);
    return;
  }

  // At or above threshold — close the PR.
  core.info(`PR #${prNumber}: at/above threshold (${failedCount}/${MAX_FAILURES}). Closing.`);
  const body = formatCloseComment(failures, results.length, author);
  await postOrUpdateComment(github, owner, repo, prNumber, body);

  await github.rest.pulls.update({
    owner,
    repo,
    pull_number: prNumber,
    state: 'closed',
  });

  core.info(`PR #${prNumber}: closed.`);
};
