# Telegram layout reference

Reference-only inspection, 20 October 2026. D-MASH remains its own product and branding. No Telegram source, artwork, icons, fonts or screenshots are bundled or copied into the MIT core. The native Qt Widgets and Android Views layout code is original. Telegram repositories retain their own GPL terms.

Desktop reference: [telegramdesktop/tdesktop](https://github.com/telegramdesktop/tdesktop/tree/86262333a457f62709726ee4ab9c48fa58824da4), master SHA `86262333a457f62709726ee4ab9c48fa58824da4`:

- `Telegram/SourceFiles/dialogs/dialogs.style`: 62px dialog row, 46px avatar, 68px name/text left, name top10/text top34; sidebar search and menu hierarchy.
- `Telegram/SourceFiles/history/view/history_view_top_bar_widget.cpp`: separate compact chat header and conversation actions.

Android reference: [DrKLO/Telegram](https://github.com/DrKLO/Telegram/tree/0aae959806c57be8ad457980f2a5c6277ff18635), master SHA `0aae959806c57be8ad457980f2a5c6277ff18635`:

- `TMessagesProj/src/main/java/org/telegram/ui/ActionBar/ActionBar.java`: 56dp portrait/48dp landscape action bar, navigation/title/action placement.
- `TMessagesProj/src/main/java/org/telegram/ui/Cells/DialogCell.java`: avatar/name/preview/time conversation row geometry.
- `TMessagesProj/src/main/java/org/telegram/ui/Components/ChatActivityEnterView.java`: compact bottom message composer and adjacent actions.

Implementation scope: sidebar/appbar navigation and search; actual conversation avatars, names and available message previews/times; separate chat header; message canvas, outgoing/incoming bubbles and timestamps; compact composer. Account and Node controls move to the menu/settings. Features without a backend are disabled with an explicit reason; no fake unread counts, online indicators, calls or attachments. Functional gates and screenshot review are required separately from compilation. Earlier teal prototype screenshots are not design acceptance.
