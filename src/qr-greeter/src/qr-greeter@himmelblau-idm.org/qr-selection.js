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
