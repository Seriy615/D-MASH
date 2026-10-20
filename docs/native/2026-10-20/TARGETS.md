# Целевые приложения

Пользователь подтвердил параллельную разработку **Android, Windows и Linux**.

| Платформа | Архитектура | Обязательная приёмка |
|---|---|---|
| Android | Форк самого Telegram Android (DrKLO/Telegram), его реальные Activities/Cells/components + отдельный D-MASH core service | APK, IPC/service lifecycle, permissions, Doze/reboot/network changes, UI flows |
| Windows | Форк самого Telegram Desktop (telegramdesktop/tdesktop), его реальные UI/models с D-MASH adapter + отдельный daemon | Executable/package, authenticated IPC/ACL, UI/process lifecycle, Windows runtime |
| Linux | Тот же форк Telegram Desktop + отдельный D-MASH daemon | Executable/package, Unix permissions/IPC, user-service lifecycle, UI flows |

Явное уточнение пользователя: «Делай прям клон телеграмма… Не отдалённо
похожее а именно клон». Самостоятельная перерисовка Widgets/Views прекращена;
ранние похожие экраны и их функциональные PASS не являются приёмкой конечного
интерфейса. Сохраняются реальные UI исходных клиентов, их навигация, компоненты,
поведение и ресурсы. Подменяется сервисная интеграция: D-MASH Account/Node вместо
Telegram backend/MTProto. Telegram SMS/login/server не становятся обязательными
для D-MASH. Нельзя выдавать демонстрационные модели/синтетические чаты или
работающий Telegram backend за интеграцию нашего ядра.

Исходники форков и изменения воспроизводятся через закреплённый upstream SHA и
открытую patch series в `clients/telegram-desktop` и `clients/telegram-android`.
Не переносить GPL-код в MIT core под чужой лицензией. У клиентов остаются
исходные GPL notices/лицензии; отдельный собственный core сохраняет MIT.

Общий C++/QuickJS actor использует проверенные Node modules через явные crypto,
storage, network и timer ports. Account E2EE/история остаются вне daemon; credential
broker не передаёт full DeviceRoot/PIN и произвольный material access сетевому
процессу. UI и daemon имеют разные lifetimes. Самоорганизация без DHT, направленные
маршруты, NAT/direct и policy relay, durable ciphertext queues, временные encrypted
file buffers и гибкие настройки входят в общую цель, а не являются исключениями.

Сохранить существующие identities/history/ownership и подтвердить миграции.
Собственный core — MIT; GPL-заимствования Telegram и зависимости сохраняют лицензии
и provenance. Документация описывает фактическую реализацию и модель угроз.
[Backlog](../../audits/2026-10-20/IMPLEMENTATION_BACKLOG.md) остаётся открытым.

Baseline product9446c22, восстановленный audit a3074a9. Рабочая копия:
`/home/jcode/D-MASH`, `codex/native-clients-20261020`. Старый Gamma WIP сохранён.
Потеря /tmp после перезапуска хоста требует повторить незакоммиченные проверки.
Пробные native compile/packaging исторические результаты не означают готовые apps.
Приложения НЕ ГОТОВЫ, цель ACTIVE; production/deploy не выполняются.
