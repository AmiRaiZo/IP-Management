## Version 4.0.3 release notes

- Add more space above mobile IP and account Edit/Delete actions so the buttons do not crowd the preceding divider or content.
- Ensure the selected color saved for each group is used directly in the group list, with fixed palette classes removed from group names and symbols.
- Bust the stylesheet cache so existing browsers load the updated responsive spacing rules.

## Version 4.0.2 release notes

- Remove the separate Group column from the desktop IP directory and the duplicate Group detail row from mobile IP cards.
- Keep the selected group badge beside each IP name and color the name to match the selected group on desktop and mobile.
- Apply the same group-badge placement and selected group text color to account records on desktop and mobile.

## Version 4.0.2 release notes

- Remove the separate Group column from the desktop IP directory and the duplicate Group detail row from mobile cards.
- Keep each selected group badge beside the IP name, and color the IP name to match that group on desktop and mobile.
- Apply the selected group color and adjacent group badge to the username/account label on desktop and mobile.

## Version 3.5.2 release notes

- Render group text, borders, and tinted backgrounds with explicit color values directly in the HTML instead of relying solely on CSS variables or color-mix rendering.
- Ensure all group-management views always provide a real fallback color; no empty group-color styles are emitted.
- Rebuild account cards with the same header, avatar, field rows, group row, spacing, and action footer as IP cards.
- Bump CSS and JavaScript cache keys to load the refreshed interface after installing the release.
- Add a regression test for saving group colors and verifying those exact colors on group management, IP records, and account cards.

## Version 3.5.1 release notes

- Removed the unnecessary internal “IP record #…” line from IP card headers.
- Applied saved group colors reliably to group names, group icons, and IP/account group badges, with a consistent fallback palette.
- Reworked account card field spacing and footer actions to match the IP cards; fixed avatar alignment and missing inner field padding.
- Bumped static asset cache keys so browsers load the corrected CSS immediately.

## Version 3.5.0 release notes

- IP and account passwords stay masked until clicked; clicking reveals and copies the value in one action.
- Added persistent per-group colors for IP groups and account groups, with a color picker on creation and a saveable color control on each existing group.
- Group labels and names use coordinated color accents across the IP and account directories.
- Desktop IP/account inventories now use the same responsive cards as mobile instead of wide record tables.
- Profile initial badges are smaller and sit before record names; Edit actions are more subtle and compact.

## Version 3.0.28 release notes

- Refresh sidebar navigation with crisp, custom line icons for IP addresses, groups, accounts, users, settings, security, and updates.
- Add soft per-section color accents, polished hover motion, and a stronger active-state icon treatment in both light and dark themes.

## Version 3.0.27 release notes

- Fix update checks when GitHub's unauthenticated REST API rate limit is exhausted by resolving the latest public release page and its verified Git tag without a personal access token.
- Add regression coverage for the rate-limit fallback.

## Version 3.0.26 release notes

- Complete the mobile IP directory with inline record details and visible edit/delete actions for authorized users, matching the Account Vault experience.
- Add Telegram Account Vault controls for browsing accounts and creating account records with roles.
- Consume Telegram one-time login codes immediately after successful use and notify the configured bot chat with the login identity and confirmation or suspicious-login actions.
- Keep desktop table headings simple and refine mobile record-field icons and spacing.
- Correct responsive regression checks to match the account card markup and actual mobile field grid sizing; refresh static asset cache keys.

## Version 3.0.25 release notes

- Complete the Telegram Account Vault workflow: browse account groups, search accounts, inspect credentials, add accounts, edit records, and confirm deletions. Account passwords remain encrypted in the database and conversation state.
- When a superadmin signs in with a Telegram one-time code, consume the stored code immediately, then notify the configured bot chat with the user, code used, and a confirmation button. The code cannot be reused.
- Replace the old mobile IP details dialog with inline detail cards matching Account Vault: group, IP address, port, username, permission-gated password, notes, and last update.
- Keep mobile IP Edit/Delete actions directly available and retain separate filtering and scroll state for IP and account lists.
- Restore simple text-only desktop table headings; use clean colored SVG icons beside record fields instead of decorating the headings.
- Add regression coverage for Account Vault bot workflows, one-time code acknowledgement, mobile details and actions, simple headers, and record-group sorting.
- Refresh CSS and JavaScript cache keys and publish v3.0.25.

## Version 3.0.24 release notes

- Finalize the independent Account Vault module with its own account records, groups, forms, and CRUD operations, isolated from the IP and IP-group tables.
- Require only the account name; username, email, and password remain optional, while a supplied email is format-validated and blank passwords on edit preserve the existing encrypted password.
- Remove the redundant account form explanation about IP groups.
- Keep the account Edit and Delete actions clearly visible on mobile, and show IP Edit/Delete actions on mobile IP cards for super administrators.
- Use consistent, crisp SVG column icons for IP and account tables with matching sizing, alignment, borders, and light/dark theme support.
- Correct responsive regression assertions to match the actual mobile action markup and verify only the intended account field is required.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.24.

## Version 3.0.23 release notes

- Keep the **Accounts** module independent from IP records and IP groups, with its own account table, groups, directory, and create/edit/delete flows.
- Make only the account name mandatory. Username, email, and password can be blank; when an email is entered, it must still be valid. A blank password on edit preserves the saved password.
- Keep the mobile Accounts cards' **Edit account** and **Delete** actions visible and easy to tap; remove the redundant note saying account groups are not shared with IP groups.
- Add visible **Edit** and **Delete** actions to mobile IP cards for super administrators; keep them separate from the tap-to-open details button and preserve search/group filters plus scroll position.
- Refine IP and Accounts table-column icons with consistent SVG artwork, alignment, spacing, and light/dark theme styling.
- Strengthen the mobile group/name sorting regression by inspecting each complete card, including the name and group metadata at the card level.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.23.

## Version 3.0.22 release notes

- Add directly visible **Edit** and **Delete** actions to each mobile IP card for super administrators, alongside the existing tap-to-open details button.
- Keep mobile IP card actions separate from the detail button, so edit and delete do not accidentally open the details modal.
- Preserve filtered search/group state and scroll position when editing or deleting IP records from a phone.
- Add consistent, compact SVG icons to IP and Accounts table headers for profile/name, group, address, port, username, email, password, and last updated.
- Style the column icons with aligned sizing and light/dark theme variants for a clearer, more polished table.
- Add regression coverage for rendered mobile IP edit/delete links, CSRF-protected delete forms, column icon order, and the shared visual style.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.22.

## Version 3.0.21 release notes

- In the separate Accounts module, make only the account name mandatory. Username, email, and password may be left blank; if an email is entered, it must still be valid.
- Allow new account records without a password and store an empty value safely; a blank password while editing continues to preserve the current saved password.
- Remove the redundant “Only account groups appear here; IP groups are not shared” note from the account form.
- Make the phone account card's **Edit account** action prominent, larger, and explicitly visible; retain a separate delete action.
- Display a dash instead of empty copy buttons when an optional username or email is blank.
- Add regression tests for saving name-only accounts, enforcing the name requirement, and confirming the account edit action appears in the list.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.21.

## Version 3.0.20 release notes

- Add a standalone **Accounts** section to save a display name, username, email address, and password for websites or services.
- Add separate **Account groups** with their own records, creation/reordering/deletion, and a dedicated Default group; IP groups and IP records stay unchanged and are never reused by this module.
- Add account creation, editing, deletion, case-insensitive search, group filtering, responsive cards, and preservation of the active filter/scroll position after edits or deletes.
- Encrypt account passwords at rest using the app's Fernet key. When editing, a blank password field keeps the current password; the directory masks passwords and provides a copy action.
- Limit the account vault and its groups to super administrators independently of IP visibility and saved-IP-password permissions.
- Add regression tests for account CRUD, at-rest encryption, email validation, access control, retention of existing passwords, safe return URLs, and separation from IP data and groups.
- Refresh CSS/JS cache keys and publish v3.0.20.

## Version 3.0.19 release notes

- Add a separate **Accounts** area for saving an account name, username, email, and password.
- Add a dedicated account-group directory and account-only group assignments; IP records and IP groups remain in their existing tables and are not mixed with account records.
- Add account creation, editing, deletion, search, group filtering, sorting by group/name, and scroll/filter preservation after edits or deletion.
- Encrypt account passwords at rest with the application's Fernet key; leave an existing password unchanged when the edit form's password field is blank. Passwords are masked in the directory and can be copied by authorized account-vault users.
- Restrict account records and account groups to super administrators independently from the IP record visibility and saved-IP-password permissions.
- Add regression tests for account CRUD, password encryption, invalid email rejection, isolated groups, preserving existing passwords, safe return URLs, and access control.
- Add separate responsive account directory and group pages, separate navigation, and cache-busted assets; publish v3.0.19.

## Version 3.0.18 release notes

- Add a Log out action to the required first-login Authenticator setup page so users can safely leave instead of enrolling immediately.
- The logout action clears the pending 2FA enrollment session and returns to sign-in; it does not disable or bypass the required per-user 2FA policy.
- Keep the action protected by the application's CSRF guard and clear any remembered 2FA cookie.
- Add API regression coverage proving that logout exits the pending session, protected pages remain inaccessible, and the next sign-in requires setup again.
- Add a template regression test for the logout form, CSRF token, and explicit reminder that 2FA remains required.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.18.

## Version 3.0.17 release notes

- Fix shared two-factor login so all accounts use the existing site-wide Authenticator code after password verification; newly created users no longer have to enroll a separate authenticator.
- Restrict the personal Authenticator setup route to the per-user policy, while keeping individual enrollment available when that policy is selected.
- Update the users list and profile to show the active global shared policy instead of a misleading per-user setup status.
- Clarify security settings so the shared Authenticator behavior is explicit.
- Add regression coverage for creating a new account under shared mode, logging in with the shared code, blocking per-account setup in shared mode, and keeping per-user enrollment intact.
- Refresh stylesheet and JavaScript cache keys and publish v3.0.17.

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

