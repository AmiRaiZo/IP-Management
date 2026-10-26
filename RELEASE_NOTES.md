## Version 3.0.16 release notes

- Sort the main IP directory by group name A–Z, case-insensitively, on desktop and mobile.
- Keep IP records sorted by their own names A–Z within each group, using the IP address as the fallback for blank names.
- Apply the group-first directory order for both superadmins and restricted users, without changing the IP-name ordering in user permissions settings.
- Add regression coverage for mixed group names and per-group record order in desktop/mobile directories and restricted-user views.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.16.

## Version 3.0.15 release notes

- Keep the current IP directory search and group filter when opening an IP record for editing and after saving or deleting it.
- Carry the filtered return URL through the edit form and delete request; restore the same scroll position after returning.
- Preserve the search/filter fields whether they were submitted via the filter form or changed with live client-side filtering.
- Restrict return redirects to the local IP directory to prevent open redirects.
- Add regression tests for the edit form, update/delete return destinations, malicious external return URLs, and front-end filter transfer.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.15.

## Version 3.0.14 release notes

- Preserve list scroll position when editing or deleting IP records, groups, and users and then returning to the list.
- Restore the same record's viewport position when it still exists; after deletion, keep the nearest row in view.
- Preserve in-progress IP search text and selected group filter across edits/deletes, including the mobile IP list.
- Add stable row markers and regression checks for scroll, filter, and return-position restoration.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.14.

## Version 3.0.13 release notes

- Sort IP records alphabetically by record name (A–Z, case-insensitive) in the main directory on desktop and mobile.
- Apply the same name-based ordering to the IP visibility list in user permission settings.
- Use the IP address as a stable fallback for records whose names are blank and keep tie ordering deterministic.
- Add regression coverage for alphabetical ordering in the superadmin directory, restricted-user directory, and access settings.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.13.

## Version 3.0.12 release notes

- Add a superadmin-only Markdown import page for existing NAME/IP/USER/PASS inventory tables.
- Provide a preview that never displays usernames or passwords, encrypt the staged source file, and expire the preview after 15 minutes.
- Parse host:port values, encrypt imported connection passwords, put new records in the Default group, and skip IP/port duplicates.
- Hold ambiguous rows (multiple IPs, usernames, or password lines) for manual review instead of guessing, and audit only aggregate counts.
- Add regression tests for successful import, password encryption and preview privacy, duplicate handling, ambiguous rows, invalid files, and role restrictions.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.12.

## Version 3.0.11 release notes

- Remove the password-security helper sentence and the "Copy current password" button from the IP edit form while retaining normal password editing and the show/hide toggle.
- Add a protected POST delete route for user accounts and a Delete action in the user list.
- Prevent self-deletion and deletion of the last enabled super administrator. Delete requests use the existing CSRF protection and are limited to super administrators; associated user access rules and temporary login/recovery codes are removed via foreign-key cascades.
- Add tests for edit-form cleanup, successful user deletion, cascade cleanup, and protection against deleting the current account.
- Update the regression test to verify that copy-password UI is absent from the edit form while copy controls remain available in the directory.
- Refresh asset cache keys and publish v3.0.11.

## Version 3.0.9 release notes

- Put Group before IP address in the desktop table and mobile details panel.
- Center the phone-sized IP name cards and detail values, standardize the card/button boxes, and add top spacing so the first card no longer touches the divider.
- Retain hover/tap feedback and blur-backed details; refresh asset cache keys so phones load the final styles/scripts.
- Harden the mobile layout regression test to validate the normalized CSS without relying on whitespace inside the version marker.

## Version 3.0.8 release notes

- Finalize the mobile directory polish: Group appears before IP address in desktop and mobile details; the mobile IP-name cards and detail values are centered with consistent button boxes.
- Add breathing room above the first mobile card so it no longer touches the divider, and refine card hover/tap feedback.
- Refresh CSS/JavaScript cache keys and keep regression coverage for ordering, text alignment, and top spacing.

## Version 3.0.7 release notes

- Move the Group column before IP address in the desktop directory and show Group first in the mobile detail dialog.
- Center mobile IP names and detail values, improve card sizing, borders and touch states, and add top padding so the first card no longer touches the divider.
- Update cache-busting keys and add regression assertions for field ordering, centered layout, and spacing.

## Version 3.0.6 release notes

- Removed the extra explanatory sentence under the IP addresses heading.
- Replaced the cramped mobile table with a clean list of IP names; opening a name shows the complete record in a centered dialog with a blurred backdrop.
- Made IP address, port, username and (only when permitted) password values tap-to-copy inside the dialog. Group and notes are displayed as readable details.
- Kept the desktop table and existing password visibility permissions unchanged.
- Added regression tests for the mobile dialog, copy actions, subtitle removal, blur effect, and permission-gated password data.
- Bumped CSS/JavaScript cache keys to v3.0.6.

## Version 3.0.5 release notes

- Fixed the mobile half-width page: the tablet rule for `body.has-sidebar:not(.sidebar-collapsed) .main-column` had higher CSS specificity than the earlier mobile override, leaving a 215px sidebar gutter on phones.
- Added a later mobile override with matching specificity so the main column always occupies the full viewport width and the content container uses its parent width rather than forcing `100vw`.
- Kept the theme toggle and welcome toast constrained within the mobile page width.
- Bumped CSS/JavaScript cache keys to v3.0.5 and added regression coverage for the exact specificity conflict.

## Version 3.0.2 release notes

- Stop formatting saved IP record names as Telegram inline-code values. Names stay ordinary readable text and are not presented as tap-to-copy fields.
- Keep IP address, port, username, and password inline-code formatted for one-tap copy in the bot's detail view and search results.
- Add regression assertions for both detail view and search results.

## Version 3.0.1 release notes

- Fixed the in-place upgrade script's embedded updater: a missing newline after the Gunicorn recovery branch caused Bash to fail at `echo "PROGRESS:84..."` before Nginx validation.
- Added a regression test that extracts the exact updater heredoc generated by `upgrade_existing.sh` and runs `bash -n` on it; the standalone updater and outer upgrade script are also syntax-checked.
- Existing installations whose privileged updater is already malformed must run the one-time in-place repair script over SSH because Bash cannot execute a malformed script far enough to self-repair it.

## Version 3.0.0 release notes

- Fix the mobile/tablet half-width canvas and blank white area by pinning the document and app shell to the visual viewport and preserving the remaining content width around the desktop drawer.
- Add regression coverage for viewport-locked layout and bump static asset cache keys to v3.0.0 so browsers fetch the fix.
- Keep README.md focused on installation, upgrade, updating, access recovery, and server-operation instructions. Release notes are published on the GitHub release page instead.
- Configure release automation to retain only the two latest published releases and delete older release entries and tags.

