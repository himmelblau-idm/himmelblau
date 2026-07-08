# Himmelblau Translations

Himmelblau uses GNU gettext catalogs for user-visible authentication messages.
The source language is English.

Recommended openSUSE Weblate component settings:

- File mask: `po/*.po`
- Template: `po/himmelblau.pot`
- New language file: `po/<lang>.po`
- Translation domain: `himmelblau`

Translator-owned files are `po/*.po` and `po/LINGUAS`. Runtime builds compile
enabled languages from `po/LINGUAS` into `target/<profile>/locale`.

Maintainer commands:

```sh
scripts/i18n-update-pot
scripts/i18n-check
```
