# D-MASH: аудит, алгоритмы и переход к приложению

Срез `transport-v3@9446c22f27309131456942870971d477f6f2358f`, 20 октября 2026. Документы ниже заменяют ранние противоречивые черновики. Android и Desktop — параллельные клиенты общего daemon contract. Готовое приложение и закрытие уязвимостей остаются целью реализации; этот каталог хранит исходные факты, проект и проверку проекта.

| Документ | Назначение |
|---|---|
| [CURRENT_IMPLEMENTATION.md](CURRENT_IMPLEMENTATION.md) | Что действительно делает код: DeviceRoot/Node/Account keys, KDF, QR profiles, directional routes, outer envelope и encrypted Inbox |
| [REPOSITORY_AUDIT.md](REPOSITORY_AUDIT.md) | Сильные стороны, найденные проблемы, исторические тесты и ограничения проверки |
| [TELEGRAM_INTEGRATION_PLAN.md](TELEGRAM_INTEGRATION_PLAN.md) | Общая архитектура, два platform host, selective Telegram UI reuse, этапы и gates |
| [IMPLEMENTATION_BACKLOG.md](IMPLEMENTATION_BACKLOG.md) | Приоритетные исправления и реализация, зависимости и проверяемые статусы |
| [NETWORK_DAEMON_ARCHITECTURE.md](NETWORK_DAEMON_ARCHITECTURE.md) | Владение, IPC, self-organization/NAT и открытые design decisions |
| [NETWORK_ALGORITHMS.md](NETWORK_ALGORITHMS.md) | Состояния, bounded алгоритмы, сбои, migration и network acceptance |
| [BUFFERED_FILES.md](BUFFERED_FILES.md) | Ciphertext staging/custody/chunks/providers/locator, offline limits и отдельный новый протокол |
| [SECURITY_CONTROLS.md](SECURITY_CONTROLS.md) | Индивидуальные настройки и немедленное применение policy, lock lifecycle |
| [verification/README.md](verification/README.md) | Исполняемые actual-source проверки и bounded fault models, результаты и пределы |
| [INDEPENDENT_REVIEW.md](INDEPENDENT_REVIEW.md) | Независимая проверка согласованности и требований, статус замечаний |
| [evidence.json](evidence.json) | SHA, среда, scope полного исходного runner/browser smoke; не native release acceptance |

Product source, production, реальные ключи/история и базы в рамках планового аудита не изменялись. Любая последующая реализация должна иметь собственный source/evidence checkpoint. Полная документация actual implementation и formal threat model входят в release backlog; этот пакет не выдаётся за завершённый криптографический аудит.
