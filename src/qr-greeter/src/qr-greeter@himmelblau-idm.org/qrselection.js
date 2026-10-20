const URL_RE = /https?:\/\/[^\s<>"')\]]+/g;

function extractUrls(message, urlRegex = URL_RE) {
    if (!message) {
        return [];
    }

    urlRegex.lastIndex = 0;
    const matches = message.match(urlRegex);
    return matches ? matches : [];
}

function findCompleteUrl(urls) {
    const userCodeMatch = urls.find(url => /[?&]user_code=|user_code%3D/i.test(url));
    if (userCodeMatch) {
        return userCodeMatch;
    }

    let best = null;
    for (const url of urls) {
        for (const other of urls) {
            if (url !== other && url.startsWith(other) && url.length > other.length) {
                if (!best || url.length > best.length) {
                    best = url;
                }
            }
        }
    }

    return best;
}

export function selectDeviceFlowUrl(
    message,
    {
        urls = null,
        urlRegex = URL_RE,
        validateUrl = url => url,
    } = {}
) {
    const matches = urls ? urls : extractUrls(message, urlRegex);
    if (matches.length === 0) {
        return { url: null, usedComplete: false, urls: [] };
    }

    const validated = [];
    for (const url of matches) {
        const normalized = validateUrl(url);
        if (normalized) {
            validated.push(normalized);
        }
    }

    if (validated.length === 0) {
        return { url: null, usedComplete: false, urls: [] };
    }

    const completeUrl = findCompleteUrl(validated);
    if (completeUrl) {
        return { url: completeUrl, usedComplete: true, urls: validated };
    }

    return { url: validated[0], usedComplete: false, urls: validated };
}

export { URL_RE };

// Extract user_code from a device flow message.
// Handles: bare 9-char codes (e.g. "E9Y6JX8J7"), hyphenated codes (e.g. "ABCD-EFGH"),
// and URL query params (?user_code=...).
// Returns null if not found.
export function extractUserCode(message) {
    if (!message) return null;
    // Match user_code parameter in URL query string
    const urlMatch = message.match(/[?&]user_code=([A-Z0-9-]+)/i);
    if (urlMatch) return urlMatch[1].toUpperCase();
    // Match "enter the code XXXXXXXXX" sentence format (Microsoft typically sends
    // 9-char codes with no hyphen, e.g. "enter the code E9Y6JX8J7 to authenticate";
    // range 6-12 is intentionally broader for forward compatibility)
    const sentenceMatch = message.match(/enter the code\s*:?\s+([A-Z0-9-]{6,12})(?![A-Z0-9-])/i);
    if (sentenceMatch) return sentenceMatch[1].toUpperCase();
    // Match hyphenated code pattern (e.g. "ABCD-EFGH") - other providers
    const hyphenMatch = message.match(/\b([A-Z0-9]{4,5}-[A-Z0-9]{4,5})\b/i);
    if (hyphenMatch) return hyphenMatch[1].toUpperCase();
    // A context-free code must occupy the entire message and contain a digit.
    // userCode only contains [A-Z0-9-] so it is safe to embed directly in SVG
    // text nodes (no XML special characters can appear from this regex)
    const bareMatch = message.trim().match(/^(?=[A-Z0-9]*[0-9])([A-Z0-9]{8,9})$/i);
    if (bareMatch) return bareMatch[1].toUpperCase();
    return null;
}
