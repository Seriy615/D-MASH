# Целевые приложения

Пользователь подтвердил параллельную разработку **Android, Windows и Linux**.

| Платформа | Архитектура | Обязательная приёмка |
|---|---|---|
| Android | Native service, отдельный Java/Kotlin Views UI | APK, IPC/service lifecycle, permissions, Doze/reboot/network changes, UI flows |
| Windows | Отдельные user daemon и Qt Widgets UI | Executable/package, authenticated IPC/ACL, UI/process lifecycle, Windows runtime |
| Linux | Отдельные user daemon и Qt Widgets UI | Executable/package, Unix permissions/IPC, user-service lifecycle, UI flows |

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
