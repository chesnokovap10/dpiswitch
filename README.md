<p align="center">
  <img src="assets/icon.png" width="96" height="96" alt="DPI Switch">
</p>

<h1 align="center">DPI Switch</h1>

<p align="center">
  <b>Клиент AmneziaWG для Windows, который сам выводит из туннеля незаблокированные сайты</b><br>
  <sub>An AmneziaWG client for Windows that takes unblocked sites out of the tunnel by itself</sub>
</p>

<p align="center">
  <img alt="Windows 10/11" src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?style=flat-square">
  <img alt="AmneziaWG" src="https://img.shields.io/badge/AmneziaWG-awg%20%2B%20awg2-2563eb?style=flat-square">
  <img alt="mihomo" src="https://img.shields.io/badge/core-mihomo-6b7280?style=flat-square">
  <img alt="Go 1.26+" src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat-square">
  <img alt="1.2.0" src="https://img.shields.io/badge/version-1.2.0-127a3d?style=flat-square">
</p>

<p align="center">
  <a href="#русский"><kbd> Русский </kbd></a>&nbsp;&nbsp;
  <a href="#english"><kbd> English </kbd></a>
</p>

<br>

## Русский

<table>
<tr>
<td width="33%" valign="top"><b>Всё через туннель</b><br><sub>По умолчанию весь трафик идёт через AmneziaWG — ничего не сломается, пока детектор не проверит.</sub></td>
<td width="33%" valign="top"><b>Детектор блокировок</b><br><sub>Сравнивает прямой путь и туннель на одном узле: TCP, TLS, HTTP, QUIC.</sub></td>
<td width="33%" valign="top"><b>Второй туннель</b><br><sub>Отдельный сервер для YouTube, Telegram, ИИ-сервисов и вашего списка.</sub></td>
</tr>
</table>

Клиент AmneziaWG для Windows на ядре [mihomo](https://github.com/MetaCubeX/mihomo).
По умолчанию весь трафик компьютера идёт через туннель AmneziaWG. Параллельно детектор проверяет
сайт за сайтом, вмешивается ли провайдер в прямой путь. Сайт, который напрямую работает и не
медленнее, переводится на прямое соединение и запоминается: он открывается быстрее и видит вашего
настоящего провайдера. Всё остальное остаётся в туннеле.

> [!IMPORTANT]
> Детектор только **выводит** сайты из туннеля, по одному и после проверки. При сомнении сайт
> остаётся в туннеле: ошибочное «чисто» ломает сайт, ошибочное «заблокирован» стоит лишь крюка
> через туннель.

### Содержание

- [Установка](#установка)
- [Интерфейс](#интерфейс)
- [Куда идёт соединение](#куда-идёт-соединение)
- [Как проверяется сайт](#как-проверяется-сайт)
- [Вердикты](#вердикты)
- [Сроки и перепроверки](#сроки-и-перепроверки)
- [Домены целиком](#домены-целиком)
- [Авто-переключение и «только наблюдать»](#авто-переключение-и-только-наблюдать)
- [Сети](#сети)
- [DNS](#dns)
- [IPv6](#ipv6)
- [Второй туннель](#второй-туннель)
- [Если сайт не открывается](#если-сайт-не-открывается)
- [Права и файлы](#права-и-файлы)
- [Команды](#команды)
- [Сборка и разработка](#сборка-и-разработка)

### Установка

`dpiswitch.exe` самодостаточен: ядро mihomo встроено внутрь, копировать больше нечего.

1. Запустите `dpiswitch.exe` — в трее появится значок.
2. Левый клик по значку — веб-интерфейс, правый — меню.
3. «Установить службу» (один запрос прав администратора). Программа копирует себя в
   `%ProgramFiles%\DPI Switch` и дальше работает оттуда: служба — от SYSTEM, трей переезжает туда же
   и ставится в автозапуск. При первой установке на рабочем столе появляется ярлык «DPI Switch».
   Запущенный вами файл больше не используется, его можно удалить.
4. Загрузите `.conf` AmneziaWG, который выдал ваш VPN-провайдер; по желанию — второй `.conf` для
   второго туннеля (awg2). Ключи остаются на этом компьютере.

> [!TIP]
> **Обновление.** Запустите новый `dpiswitch.exe` откуда угодно: он предложит установить себя поверх
> установленной версии (один запрос прав администратора) и перенесёт трей на неё.

**Удаление.** Внизу боковой панели интерфейса:

- «Удалить службу…» — туннель останавливается и не запускается с Windows, пока службу не установят
  снова; программа, настройки и списки остаются.
- «Удалить программу…» — полное удаление (один запрос прав администратора): останавливается и
  удаляется служба, закрывается трей, удаляются `%ProgramFiles%\DPI Switch`, `%ProgramData%\dpiswitch`
  (с файлами `.conf` и их ключами), папка трея в профиле, автозапуск и ярлык на рабочем столе. Остаётся
  только файл, из которого программу устанавливали.

> [!CAUTION]
> Удаление программы необратимо: если файлы `.conf` ещё понадобятся, сохраните их копию заранее.

### Интерфейс

Веб-интерфейс открывается из трея и работает только на этом компьютере (`127.0.0.1`, у каждого
пользователя свой порт и свой ключ доступа).

| Страница | Что там |
|---|---|
| **Обзор** | Сколько сайтов идёт напрямую, заблокировано, медленнее, не проверено; состояние обоих туннелей, замена `.conf`; последние события |
| **Вердикты** | Все вердикты по вкладкам «Напрямую», «Заблокированы», «Медленнее», «Не проверено», фильтр по имени, «Сбросить все вердикты…» |
| **Списки маршрутов** | «Всегда напрямую», «Всегда через туннель», «Программы в обход туннеля» |
| **Второй туннель** | Подключение awg2, пресеты (YouTube, Telegram, ИИ-сервисы, Instagram/Facebook/X) и свои сайты |
| **Настройки** | Детектор, сроки, IPv6, DNS; каждое изменение применяется сразу |
| **Логи** | Лог контроллера и службы, ядра, трея и интерфейса |
| **Справка** | То, что описано ниже; ссылки из неё ведут прямо к нужному полю, и оно подсвечивается |
| **Live** | Соединения ядра раз в секунду: программа, хост, IP, порт, тип (TLS, QUIC, HTTP…), маршрут, скорость и объём в обе стороны; открытые, простаивающие и закрытые, цвет строки — маршрут. Ядро опрашивается, только пока страница на экране |

В шапке — состояние службы и туннелей, переключатель авто-переключения и кнопка «Старт»/«Стоп».
Внизу боковой панели — установка и удаление службы, автозапуск трея и выбор языка (English / Русский).
Трей говорит на том же языке, что и интерфейс.

**Меню трея:** «Настройки…» (открыть интерфейс), «Установить службу…» / «Остановить туннель» /
«Запустить туннель», «Всё через туннель (сбросить вердикты)», «Запускать с Windows», «Папка данных»,
«Выход». Цвет значка показывает состояние: выключен, туннель работает, ошибка. Подсказка значка —
сколько сайтов идёт напрямую и сколько заблокировано.

**Настройки по умолчанию:**

| Параметр | По умолчанию | Смысл |
|---|---|---|
| Авто-переключение | Вкл | Незаблокированные сайты идут напрямую; «Только наблюдать» — всё через туннель |
| Домены целиком | Распространять на домен | 3+ чистых поддомена и ни одного заблокированного — весь домен напрямую |
| Допуск по задержке | 20 % | Насколько прямой путь может быть медленнее туннеля и всё ещё использоваться |
| Попыток на пробу | 3 | Сайт чистый, только если чисты все попытки |
| Держать напрямую | 7 дней | Сколько чистый сайт идёт напрямую до следующей проверки |
| Перепроверять заблокированные через | 1 час | Затем всё реже, до потолка паузы |
| Потолок паузы | 1 день | Самая долгая пауза между проверками сайта |
| IPv6 | Через туннель | Даёт IPv6 даже там, где у провайдера его нет |
| DNS для прямых сайтов | `https://77.88.8.8/dns-query`, `tls://77.88.8.1` | Яндекс DoH/DoT, мимо туннеля |
| DNS внутри туннеля | из `.conf` | Для сайтов, идущих через туннель |

### Куда идёт соединение

Каждое новое соединение сверяется с правилами сверху вниз; решает первое подошедшее.

| № | Правило | Маршрут |
|---|---|---|
| 1 | Сами серверы туннелей | напрямую (иначе туннель зациклится сам в себя) |
| 2 | Адреса внутри туннелей (их DNS-сервер) | этот туннель |
| 3 | Локальные сети: роутер, принтеры, общие папки, имена `.local` и `.lan` | напрямую |
| 4 | Программы в обход туннеля (`qbittorrent.exe` и т. п.) | напрямую, весь их трафик |
| 5 | Второй туннель: пресеты и ваши сайты | awg2; если он лежит — awg; если лежат оба — напрямую |
| 6 | Всегда через туннель | awg |
| 7 | Всегда напрямую | напрямую |
| 8 | Вердикты детектора: чистые имена и адреса, на которых их проверяли (для соединений без имени) | напрямую |
| 9 | Всё остальное | awg; если он лежит — напрямую |

Ядро решает один раз — когда соединение открывается. Когда вы меняете список или пресет, открытые
соединения, которые это изменение переносит, закрываются, и программы переподключаются уже по новому
маршруту. Выключение авто-переключения закрывает соединения, которые детектор пустил напрямую.

### Как проверяется сайт

1. Детектор смотрит на соединения, которые несёт ядро, и берёт из них имена сайтов (имя читается из
   самого соединения, так что программы со своим DNS тоже попадают).
2. Имя резолвится через DNS для прямых сайтов — получается тот узел, куда реально пойдёт трафик.
3. К этому **же самому узлу** подключаемся дважды: напрямую и через туннель. На каждом пути:
   TCP-соединение, TLS-рукопожатие с именем сайта (SNI) и полной проверкой цепочки сертификатов,
   HTTP-запрос и ответ. Имя, замеченное на UDP 443, пробуется ещё и по QUIC (HTTP/3). Проверяются те
   порты, на которых имя реально использовалось.
4. Это повторяется несколько раз (попыток на пробу). Имя чистое, только если чисты все попытки и
   прямой путь не медленнее туннеля больше допуска.

Проверяется до 20 имён в минуту. Проверки встают на паузу, пока туннель не проходит собственные
проверки ядра, и на один цикл после сна или смены сети: замеры тогда говорили бы больше о моменте,
чем о пути.

### Вердикты

| Вердикт | Что увидели | Маршрут |
|---|---|---|
| 🟢 `CLEAN` | Все попытки прошли напрямую так же, как через туннель, и не медленнее | напрямую |
| 🔴 `BLOCKED_TCP` | Напрямую соединение отклоняется, сбрасывается или висит, а через туннель работает | туннель |
| 🔴 `BLOCKED_TLS` | TCP устанавливается, но TLS-рукопожатие обрывается, как только видно имя сайта: типичная блокировка DPI | туннель |
| 🔴 `BLOCKED_QUIC` | Напрямую заблокирован QUIC (UDP 443). TCP может работать, но имя идёт одним маршрутом целиком | туннель |
| 🔴 `MITM` | Сертификат на прямом пути не сайта или не проходит проверку: вместо сайта отвечает кто-то другой | туннель |
| 🔴 `CONTENT_DIFF` | Ответ на прямом пути отличается от туннельного: скорее всего, страница-заглушка | туннель |
| 🟡 `SLOWER` | Не заблокирован, но напрямую медленнее туннеля сверх допуска | туннель |
| ⚪ `INCONCLUSIVE` | Не с чем сравнить: туннель тоже не прошёл, сайт нигде не отвечает или его IPv6-узел напрямую недоступен | остаётся прежний вердикт; новое имя остаётся в туннеле |

### Сроки и перепроверки

- Чистый сайт идёт напрямую заданный срок (по умолчанию 7 дней), потом его проверяют снова. Если
  проверка не может это подтвердить, он идёт через туннель до следующей.
- Сайт, один раз оказавшийся медленнее, не возвращается в туннель сразу: его перемеряют через
  интервал перепроверки, и только второе «медленнее» подряд возвращает его в туннель.
- Заблокированный сайт пробуют снова через интервал перепроверки (по умолчанию час). Каждая проверка
  подряд с тем же итогом удваивает ожидание — до потолка паузы (сутки).
- Имена перепроверяются, только пока к ним кто-то ходит. Имя, к которому сутки никто не обращался,
  оставляют в покое, а через десять дней забывают.

### Домены целиком

Когда у домена 3 и больше чистых поддоменов и ни одного заблокированного, медленного или не
работающего напрямую, напрямую идёт весь домен (`+.example.com`): новые поддомены не ждут проверки
и проверяются уже потом. Первый плохой поддомен снимает правило. Помогает сервисам с пулом серверов:
CDN, спидтестам, обновлениям.

### Авто-переключение и «только наблюдать»

**Вкл**: вердикты применяются. **Только наблюдать**: всё идёт через туннель, детектор продолжает
проверять и записывать, а в логе видно, что пошло бы напрямую. Переключение применяется за секунду.
При выключении открытые соединения, которые детектор пустил напрямую, закрываются, и программы
переподключаются через туннель. При включении уже открытые соединения остаются в туннеле, напрямую
идут новые. Вердикты сохраняются в обоих режимах.

### Сети

Вердикты хранятся по провайдеру (его номеру AS), а не по Wi-Fi-сети: другая сеть того же провайдера
пользуется ими же, другой провайдер начинает свои. Без сети проверки встают на паузу, память
сохраняется.

### DNS

- **Прямые сайты** резолвятся DNS для прямых сайтов, мимо туннеля: CDN отвечают узлами рядом с вашим
  провайдером. Детектор пользуется теми же серверами, так что проверяет тот узел, куда пойдёт трафик.
  Надёжнее всего DoH или DoT по адресу (`https://IP/dns-query`, `tls://IP`): многие провайдеры
  блокируют или подменяют обычный DNS. Кнопка «Проверить» в настройках опрашивает каждый сервер.
- **Сайты через туннель** резолвятся внутри туннеля, его DNS (из `.conf`, если не задан свой).
- Программы получают от ядра подставные адреса (fake-ip: `198.18.0.0/16`, `2001:2::/48`), а настоящий
  ядро узнаёт уже на выбранном маршруте. Поэтому маршрут решает имя, а не адрес. Диапазон IPv6
  намеренно не ULA: Chrome считает `fc00::/7` локальной сетью и блокирует запросы к ней (Local Network
  Access).

> [!NOTE]
> Сохранение DNS перезапускает ядро: туннель пропадает на пару секунд.

### IPv6

С включённым IPv6 у компьютера есть IPv6, даже если у провайдера его нет: он идёт через туннель.
Прямые сайты ходят по IPv4. Если у сервера туннеля IPv6 не работает, программа это замечает и
резолвит для него только IPv4. Переключение перезапускает ядро.

### Второй туннель

Второй сервер AmneziaWG только для выбранных сервисов: YouTube, Telegram, ИИ-сервисов (ChatGPT,
Claude, Gemini, Grok, Copilot, DeepL и др.), Instagram, Facebook, X и вашего списка. Он стоит выше
всех остальных списков, детектор его имена не трогает. Если он лежит, его сайты идут через первый
туннель; если лежат оба — напрямую. Пока он не подключён, пресеты идут через первый туннель. Все
пресеты по умолчанию выключены. Переключение пресета применяется сразу, включая открытые соединения.

### Если сайт не открывается

1. Найдите его фильтром на странице **Вердикты**. Если он идёт напрямую, а не должен, добавьте его во
   **Всегда через туннель** (`+.example.com` — весь домен).
2. Если сломалось сразу много сайтов (провайдер ввёл новую блокировку), **сбросьте все вердикты** —
   на странице «Вердикты» или пунктом трея «Всё через туннель»: всё пойдёт через туннель, и детектор
   начнёт заново.
3. Если сайт должен видеть ваш настоящий адрес (банк, госуслуги), добавьте его во **Всегда напрямую**.
4. В **логах** виден каждый вердикт с причиной.
5. На странице **Live** видно, каким маршрутом и по какому правилу идут его соединения прямо сейчас.

### Права и файлы

Служба принадлежит пользователю, который её установил: только он (и администраторы) может запускать
и останавливать её и менять настройки, списки и конфиги. Остальные учётные записи на компьютере видят
только её состояние.

- `%ProgramFiles%\DPI Switch` — программа; служба и трей запускаются отсюда.
- `%ProgramData%\dpiswitch` — данные службы: конфиг ядра, вердикты (`controller-state.json`), каждая
  проба (`reports.jsonl`), логи (`logs\service.log`, `logs\mihomo.log`). Писать туда могут только
  SYSTEM и администраторы, пользователи — читать.
- `%ProgramData%\dpiswitch\user` — то, что вы меняете в интерфейсе: `.conf`, списки, настройки.
  Писать туда можете только вы; служба это читает и никогда туда не пишет. Файлы с приватными
  ключами читаете только вы и служба.
- `%ProgramData%\dpiswitch\core\mihomo.exe` — ядро, которое служба распаковывает из себя; перед каждым
  запуском сверяется SHA-256, при несовпадении распаковывается заново.
- `%LOCALAPPDATA%\dpiswitch` — трей: его лог (`tray.log`), ключ интерфейса (`ui.key`) и выбранный язык.

### Команды

```
dpiswitch            трей (по умолчанию)
dpiswitch install    установить службу
dpiswitch uninstall  удалить службу
dpiswitch reinstall  переустановить службу
dpiswitch remove     удалить программу целиком (служба, файлы, данные)
dpiswitch version    показать версию
```

### Сборка и разработка

Нужен Go 1.26+.

```powershell
.\build.ps1
```

Результат — один файл `dist\dpiswitch.exe` со встроенным ядром mihomo (сжато gzip, всего ~24 МБ).
При первой сборке ядро собирается скриптом `tools\build-mihomo.ps1` в `dist\mihomo.exe` и потом
переиспользуется (удалите его, чтобы пересобрать). Скрипт закрепляет проверенный коммит mihomo и
оставляет только нужное DPI Switch: исходящий WireGuard (AmneziaWG), входящие TUN и SOCKS; остальные
протоколы, gVisor, встроенные Tailscale, ZeroTier и EasyTier и отладочные символы выброшены: ~30 МБ
вместо ~80 МБ. TUN работает на сетевом стеке Windows (`stack: system`).

- `.\build.ps1 -NoEmbed` — сборка без ядра для разработки; тогда `mihomo.exe` должен лежать рядом с
  `dpiswitch.exe`.
- `.\build.ps1 -Race` — отладочная сборка с детектором гонок Go в `dist\dpiswitch-race.exe`, версия
  `<версия>-race`, символы сохранены; заодно гоняет тесты под детектором. Нужны cgo и gcc
  (`winget install BrechtSanders.WinLibs.POSIX.UCRT`). Служба пишет stderr, куда идут отчёты о гонках,
  в `%ProgramData%\dpiswitch\logs\service.log`. Работает в разы медленнее и прожорливее релиза.
- `.\tools\deploy.ps1` (`-Race` — отладочная сборка, `-Path <exe>` — любая другая) заменяет
  установленный файл: закрывает трей, останавливает службу и ждёт её, копирует с повторами, запускает
  всё обратно и сверяет хеш. Заменённый файл остаётся рядом как `dpiswitch.last.exe` — `-Path` с ним и
  есть путь назад. Один раз просит права администратора: файл службы лежит в Program Files. Служба,
  зарегистрированная где-то ещё (старая установка), переустанавливается из сборки и тем самым
  переезжает туда.
- `go run ./tools/uidev [-addr 127.0.0.1:8766]` — веб-интерфейс без трея, для работы над страницами
  (шаблоны и статика встроены через embed, после правки нужна пересборка). Укажите `ProgramData` на
  копию папки данных, чтобы не трогать настоящие настройки; служба и её ядро при этом настоящие.
  Откройте адрес с ключом, который он печатает.

Проверки перед пушем запускаются локально: `go vet ./...`, `go test ./...` и для `internal/ctl` —
`go test -race` (`.\build.ps1` сам гоняет vet и тесты перед сборкой).

<p align="right"><a href="#readme">↑ наверх</a></p>

<br>

## English

<p align="right"><a href="#русский"><kbd> Русский ↑ </kbd></a></p>

<table>
<tr>
<td width="33%" valign="top"><b>Everything via the tunnel</b><br><sub>By default all traffic goes through AmneziaWG — nothing breaks before the detector has checked.</sub></td>
<td width="33%" valign="top"><b>A block detector</b><br><sub>Compares the direct path and the tunnel on the same node: TCP, TLS, HTTP, QUIC.</sub></td>
<td width="33%" valign="top"><b>A second tunnel</b><br><sub>A separate server for YouTube, Telegram, AI services and your own list.</sub></td>
</tr>
</table>

An AmneziaWG client for Windows built on the [mihomo](https://github.com/MetaCubeX/mihomo) core.
All traffic of the computer goes through the AmneziaWG tunnel by default. Alongside, a detector
checks, site by site, whether your ISP interferes with the direct path. A site that works direct,
and is not slower there, is switched to a direct connection and remembered: it opens faster and sees
your real ISP. Everything else stays in the tunnel.

> [!IMPORTANT]
> The detector only ever **takes sites out** of the tunnel, one at a time, after checking them. When
> in doubt a site stays in the tunnel: a wrong "clean" breaks a site, a wrong "blocked" only costs a
> detour.

### Contents

- [Installation](#installation)
- [The interface](#the-interface)
- [Where a connection goes](#where-a-connection-goes)
- [How a site is checked](#how-a-site-is-checked)
- [Verdicts](#verdicts)
- [Terms and re-checks](#terms-and-re-checks)
- [Whole domains](#whole-domains)
- [Auto-switch and observe only](#auto-switch-and-observe-only)
- [Networks](#networks)
- [DNS](#dns-1)
- [IPv6](#ipv6-1)
- [The second tunnel](#the-second-tunnel)
- [When a site does not open](#when-a-site-does-not-open)
- [Permissions and files](#permissions-and-files)
- [Commands](#commands)
- [Build and development](#build-and-development)

### Installation

`dpiswitch.exe` is self-contained: the mihomo core is embedded, there is nothing else to copy.

1. Run `dpiswitch.exe` — a tray icon appears.
2. Left click the icon — the web UI; right click — the menu.
3. "Install service" (one administrator prompt). The program copies itself to
   `%ProgramFiles%\DPI Switch` and runs from there: the service as SYSTEM, and the tray moves there
   too, with autostart. A first install puts a "DPI Switch" shortcut on the desktop. The file you
   started is no longer used and may be deleted.
4. Load the AmneziaWG `.conf` your VPN provider gave you; optionally a second `.conf` for the second
   tunnel (awg2). Keys stay on this machine.

> [!TIP]
> **Updating.** Start the new `dpiswitch.exe` from anywhere: it offers to install itself over the
> installed version (one administrator prompt) and moves the tray to it.

**Removing.** At the bottom of the UI's sidebar:

- "Remove service…" — the tunnel stops and does not start with Windows until the service is installed
  again; the program, settings and lists stay.
- "Remove the program…" — a complete removal (one administrator prompt): the service stops and is
  removed, the tray closes, and `%ProgramFiles%\DPI Switch`, `%ProgramData%\dpiswitch` (the `.conf`
  files and their keys included), the tray's folder in the profile, autostart and the desktop shortcut
  are deleted. Only the file the program was installed from stays.

> [!CAUTION]
> Removing the program cannot be undone: keep a copy of your `.conf` files first if you will need them.

### The interface

The web UI opens from the tray and is reachable from this computer only (`127.0.0.1`, each user has
their own port and access key).

| Page | What is there |
|---|---|
| **Overview** | How many sites go direct, are blocked, slower, unverified; both tunnels' state, replacing a `.conf`; recent events |
| **Verdicts** | Every verdict in the "Direct", "Blocked", "Slower", "Unverified" tabs, a name filter, "Reset all verdicts…" |
| **Routing lists** | "Always direct", "Always via tunnel", "Programs bypassing the tunnel" |
| **Second tunnel** | Attaching awg2, presets (YouTube, Telegram, AI services, Instagram/Facebook/X) and your own sites |
| **Settings** | Detector, terms, IPv6, DNS; every change applies at once |
| **Logs** | The controller and service log, the core's, the tray and UI's |
| **Help** | What is described below; its links lead straight to the field meant, which blinks |
| **Live** | The core's connections, every second: the program, host, IP, port, type (TLS, QUIC, HTTP…), route, speed and bytes both ways; open, idle and closed, a row coloured by its route. The core is asked only while the page is in view |

The header shows the service and tunnels' state, the auto-switch toggle and Start/Stop. The bottom
of the sidebar holds installing and removing the service, the tray's autostart and the language
(English / Русский). The tray speaks the same language as the UI.

**Tray menu:** "Settings…" (opens the UI), "Install service…" / "Stop tunnel" / "Start tunnel",
"Everything via tunnel (reset verdicts)", "Start with Windows", "Data folder", "Exit". The icon's
colour shows the state: off, tunnel up, error. Its tooltip tells how many sites go direct and how
many are blocked.

**Default settings:**

| Setting | Default | Meaning |
|---|---|---|
| Auto-switch | On | Unblocked sites go direct; "Observe only" — everything through the tunnel |
| Whole domains | Extend to the domain | 3+ clean subdomains and none blocked — the whole domain goes direct |
| Latency tolerance | 20 % | How much slower than the tunnel the direct path may be and still be used |
| Attempts per probe | 3 | A site is clean only if every attempt is |
| Keep direct for | 7 days | How long a clean site goes direct before it is checked again |
| Re-check blocked after | 1 hour | Then less and less often, up to the pause cap |
| Pause cap | 1 day | The longest wait between checks of a site |
| IPv6 | Through the tunnel | Gives IPv6 even where the ISP has none |
| DNS for direct sites | `https://77.88.8.8/dns-query`, `tls://77.88.8.1` | Yandex DoH/DoT, outside the tunnel |
| DNS inside the tunnel | from the `.conf` | For the sites that go through the tunnel |

### Where a connection goes

Every new connection is matched against these rules from the top; the first one that fits decides.

| # | Rule | Route |
|---|---|---|
| 1 | The tunnel servers themselves | direct (otherwise the tunnel would loop into itself) |
| 2 | Addresses inside the tunnels (their DNS server) | that tunnel |
| 3 | Local networks: the router, printers, shares, `.local` and `.lan` names | direct |
| 4 | Programs bypassing the tunnel (`qbittorrent.exe`, etc.) | direct, all their traffic |
| 5 | Second tunnel: presets and your sites | awg2; if it is down, awg; if both are down, direct |
| 6 | Always via tunnel | awg |
| 7 | Always direct | direct |
| 8 | Detector verdicts: names found clean, and the addresses they were probed on (for connections that carry no name) | direct |
| 9 | Everything else | awg; if it is down, direct |

The core decides once, when a connection opens. When you change a list or a preset, the open
connections the change moves are closed, and the programs reconnect over the new route. Turning
auto-switch off closes the connections the detector sent direct.

### How a site is checked

1. The detector watches the connections the core carries and picks up the names in them (the name
   is read from the connection itself, so programs with their own DNS count too).
2. The name is resolved through the DNS for direct sites: the node that traffic would really go to.
3. That **same node** is contacted twice: directly and through the tunnel. On each path: TCP
   connection, TLS handshake with the name in it (SNI) and a full certificate chain check, an HTTP
   request and its answer. A name seen on UDP 443 is also tried over QUIC (HTTP/3). The ports the
   name was really used on are the ones probed.
4. This is repeated several times (attempts per probe). The name is clean only if every attempt is
   clean, and the direct path is not slower than the tunnel by more than the tolerance.

Up to 20 names are checked a minute. The checks pause while the tunnel fails the core's own health
checks, and for a cycle after sleep or a network change: the measurements would say more about that
moment than about the path.

### Verdicts

| Verdict | What was seen | Route |
|---|---|---|
| 🟢 `CLEAN` | Every attempt passed directly just as through the tunnel, not slower | direct |
| 🔴 `BLOCKED_TCP` | The connection is refused, reset or times out directly, and works through the tunnel | tunnel |
| 🔴 `BLOCKED_TLS` | TCP connects, but the TLS handshake is cut once the site's name is seen: the typical DPI block | tunnel |
| 🔴 `BLOCKED_QUIC` | QUIC (UDP 443) is blocked directly. TCP may work, but a name goes one way as a whole | tunnel |
| 🔴 `MITM` | The certificate on the direct path is not the site's, or does not verify: someone answers in the site's place | tunnel |
| 🔴 `CONTENT_DIFF` | The answer on the direct path differs from the tunnel's: most likely a block page | tunnel |
| 🟡 `SLOWER` | Not blocked, but slower direct than through the tunnel beyond the tolerance | tunnel |
| ⚪ `INCONCLUSIVE` | Nothing to compare: the tunnel failed too, the site answers nowhere, or its IPv6 node is out of reach directly | keeps the previous verdict; a new name stays in the tunnel |

### Terms and re-checks

- A clean site goes direct for the term set (7 days by default), then it is checked again. If the
  check cannot confirm it, it goes through the tunnel until the next one.
- A site found slower once is not reverted at once: it is measured again after the re-check
  interval, and only a second "slower" in a row sends it back to the tunnel.
- A blocked site is tried again after the re-check interval (1 hour by default). Each check in a row
  that finds the same doubles the wait, up to the pause cap (1 day).
- Names are re-checked only while something still goes to them. One nothing has used for a day is
  left alone, and after ten days it is forgotten.

### Whole domains

When a domain has 3 or more clean subdomains and none blocked, slower or failing directly, the whole
domain (`+.example.com`) goes direct: new subdomains do not wait for a check and are verified
afterwards. The first bad subdomain removes the rule. It helps services with pools of servers: CDNs,
speed tests, updates.

### Auto-switch and observe only

**On**: the verdicts are applied. **Observe only**: everything goes through the tunnel, the detector
keeps checking and recording, and the log shows what would go direct. Switching applies within a
second. Turning it off closes the open connections the detector sent direct, and the programs
reconnect through the tunnel. Turning it on leaves open connections in the tunnel; new ones go
direct. The verdicts are kept either way.

### Networks

Verdicts are kept per ISP (its AS number), not per Wi-Fi network: another network of the same ISP
shares them, another ISP starts its own. Without a network the checks pause and the memory is kept.

### DNS

- **Direct sites** are resolved by the resolvers for direct sites, asked outside the tunnel: CDNs
  then answer with nodes near your ISP. The detector uses the same resolvers, so it tests the node
  the traffic will go to. DoH or DoT by address (`https://IP/dns-query`, `tls://IP`) is the safe
  choice: many ISPs block or tamper with plain DNS. The "Test" button in the settings asks each
  server.
- **Tunnelled sites** are resolved inside the tunnel, by its DNS (from the `.conf` unless set).
- Programs get stand-in addresses from the core (fake-ip: `198.18.0.0/16`, `2001:2::/48`) and the
  core resolves the real one on the chosen route. That is why a name, not an address, decides the
  route. The IPv6 range is deliberately not ULA: Chrome treats `fc00::/7` as a local network and
  blocks requests to it (Local Network Access).

> [!NOTE]
> Saving the DNS restarts the core: the tunnel drops for a couple of seconds.

### IPv6

With IPv6 on, the computer gets IPv6 even where the ISP has none: it goes through the tunnel. Sites
going direct use IPv4. If the tunnel's server has no working IPv6, the program finds out and
resolves IPv4 only for it. Changing it restarts the core.

### The second tunnel

A second AmneziaWG server for chosen services only: YouTube, Telegram, AI services (ChatGPT, Claude,
Gemini, Grok, Copilot, DeepL and more), Instagram, Facebook, X and your own list. It stands above
every other list, the detector leaves its names alone. If it is down, its sites go through the first
tunnel; if both are down, direct. Until it is attached, its presets use the first tunnel. Every
preset is off by default. A preset switch applies at once, open connections included.

### When a site does not open

1. Look it up on the **Verdicts** page with the filter. If it goes direct and should not, add it to
   **Always via tunnel** (`+.example.com` for the whole domain).
2. If many sites broke at once (a new block by the ISP), **reset all verdicts** — on the Verdicts
   page or with the tray's "Everything via tunnel": everything goes through the tunnel and the
   detector starts over.
3. If a site must see your real address (a bank, government services), add it to **Always direct**.
4. The **logs** show every verdict with its reason.
5. The **Live** page shows which route its connections take right now, and by which rule.

### Permissions and files

The service belongs to the user who installed it: only that user (and administrators) may start and
stop it and change its settings, lists and configs. Other accounts on the machine may only see its
state.

- `%ProgramFiles%\DPI Switch` — the program; the service and the tray run from here.
- `%ProgramData%\dpiswitch` — the service's own data: the core's config, the verdicts
  (`controller-state.json`), every probe (`reports.jsonl`), the logs (`logs\service.log`,
  `logs\mihomo.log`). Writable by SYSTEM and Administrators only, readable by users.
- `%ProgramData%\dpiswitch\user` — what you change in the UI: the `.conf` files, lists, settings.
  Writable by you alone; the service reads it and never writes there. Files holding private keys are
  readable by you and the service only.
- `%ProgramData%\dpiswitch\core\mihomo.exe` — the core, which the service extracts from itself; its
  SHA-256 is verified before every start, and it is re-extracted if it does not match.
- `%LOCALAPPDATA%\dpiswitch` — the tray's: its log (`tray.log`), the UI key (`ui.key`) and the
  language chosen.

### Commands

```
dpiswitch            tray (default)
dpiswitch install    install the service
dpiswitch uninstall  remove the service
dpiswitch reinstall  reinstall the service
dpiswitch remove     remove the whole program (service, files, data)
dpiswitch version    show the version
```

### Build and development

Requires Go 1.26+.

```powershell
.\build.ps1
```

The result is a single `dist\dpiswitch.exe` with the mihomo core embedded inside (gzip-compressed,
~24 MB in total). On the first build the core is built by `tools\build-mihomo.ps1` into
`dist\mihomo.exe` and reused afterwards (delete it to rebuild). It pins the tested mihomo commit and
keeps only what DPI Switch uses: the WireGuard outbound (AmneziaWG) and the TUN and SOCKS inbounds;
every other protocol, gVisor, the embedded Tailscale, ZeroTier and EasyTier and the debug symbols
are left out: ~30 MB instead of ~80 MB. The TUN runs on the Windows network stack (`stack: system`).

- `.\build.ps1 -NoEmbed` builds without the core, for development; then `mihomo.exe` must sit next
  to `dpiswitch.exe`.
- `.\build.ps1 -Race` makes a debug build with the Go race detector into
  `dist\dpiswitch-race.exe`, version `<version>-race`, symbols kept; it also runs the tests under the
  detector. It needs cgo and gcc (`winget install BrechtSanders.WinLibs.POSIX.UCRT`). The service
  sends its stderr, where race reports go, to `%ProgramData%\dpiswitch\logs\service.log`. Expect it
  to be several times slower and hungrier than the release build.
- `.\tools\deploy.ps1` (`-Race` for the debug build, `-Path <exe>` for any other) replaces the
  installed binary: it closes the tray, stops the service and waits for it, copies with retries,
  starts both again and checks the hash. The replaced binary is kept beside it as
  `dpiswitch.last.exe` — `-Path` with it is the way back. It asks for administrator rights once: the
  service's binary is in Program Files. A service still registered elsewhere (an older installation)
  is reinstalled from the build, which moves it there.
- `go run ./tools/uidev [-addr 127.0.0.1:8766]` serves the web UI without the tray, for working on
  the pages (the templates and static files are embedded, so a change needs a rebuild). Point
  `ProgramData` at a copy of the data directory to leave the real settings alone; the service and
  its core are still the real ones. Open the address with the key it prints.

Checks run locally before a push: `go vet ./...`, `go test ./...` and, for `internal/ctl`,
`go test -race` (`.\build.ps1` runs vet and the tests itself before building).

<p align="right"><a href="#readme">↑ back to top</a> · <a href="#русский">Русский</a></p>
