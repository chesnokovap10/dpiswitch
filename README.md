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
  <img alt="1.7.0" src="https://img.shields.io/badge/version-1.7.0-127a3d?style=flat-square">
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
- [Авто-переключение: вкл, «только наблюдать», «только в туннель»](#авто-переключение-вкл-только-наблюдать-только-в-туннель)
- [Сети](#сети)
- [DNS](#dns)
- [IPv6](#ipv6)
- [Второй туннель](#второй-туннель)
- [Live](#live)
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
| **Вердикты** | Все вердикты по вкладкам «Напрямую», «Заблокированы», «Медленнее», «Не проверено», фильтр по имени (русские имена ищутся и показываются как есть); строка выделяется кликом, правый клик отправляет её в список, ✕ сбрасывает её вердикт; «Сбросить все вердикты…» |
| **Списки маршрутов** | «Всегда напрямую», «Всегда через туннель», «Запрещено»: сайты, адреса и программы в каждом |
| **Второй туннель** | Подключение awg2, пресеты (YouTube, Telegram, ИИ-сервисы, Instagram/Facebook/X; их можно изменить, удалить и добавить свои) и свои сайты |
| **Настройки** | Детектор, сроки, IPv6, DNS; каждое изменение применяется сразу |
| **Логи** | Лог контроллера и службы, ядра, трея и интерфейса; последние 400 строк, вместе с предыдущим файлом после ротации |
| **Справка** | То, что описано ниже; ссылки из неё ведут прямо к нужному полю, и оно подсвечивается |
| **Live** | Соединения ядра раз в секунду — открытые, закрытые, ошибки и запрещённые попытки за весь запуск ядра; щелчок закрепляет строку, правый щелчок отправляет её сайт, адрес или программу в нужный список. Подробнее — в разделе [Live](#live) |

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
| Авто-переключение | Вкл | Незаблокированные сайты идут напрямую; «Только наблюдать» — всё напрямую, кроме списков (белый список); «Только в туннель» — всё, кроме «Всегда напрямую», через туннели и никогда напрямую. Вердикты записываются в любом режиме |
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
| 3 | Запрещено: программы, сайты, адреса | отказ, в любом режиме |
| 4 | Локальные сети: роутер, принтеры, общие папки, имена `.local` и `.lan` | напрямую |
| 5 | Всегда через туннель: программы, сайты, адреса | awg1; если он лежит — awg2, пока он включён; напрямую никогда |
| 6 | Всегда напрямую: программы (`qbittorrent.exe` и т. п.), сайты, адреса | напрямую, в любом режиме |
| 7 | Второй туннель, пока загружен и включён: пресеты и ваш список | awg2; если он лежит — awg1; затем напрямую, а в «Только в туннель» отклоняется |
| 8 | Всё остальное, пока выбрано «Только наблюдать» | напрямую |
| 9 | Вердикты детектора: чистые имена и адреса, на которых их проверяли (для соединений без имени) | напрямую |
| 10 | Всё остальное | по режиму: во «Вкл» awg1, затем awg2 (если включён), затем напрямую; в «Только в туннель» те же туннели, но никогда напрямую |

Без конфига первого туннеля служба всё равно работает: Live показывает трафик, списки действуют, а детектор
ничего не проверяет — ему не с чем сравнивать. Второй туннель, если загружен только он, берёт свои пресеты и
список и «Всегда через туннель», а в «Только в туннель» — всё. Подробные таблицы для каждого режима и набора
загруженных конфигов — в справке программы.

Строка, вписанная в несколько списков, идёт по тому, что выше в таблице: «Запрещено» → «Всегда через
туннель» → «Всегда напрямую» → пресеты и список awg2 → детектор.

Ядро решает один раз — когда соединение открывается. Когда вы меняете список или пресет, открытые
соединения, которые это изменение переносит, закрываются, и программы переподключаются уже по новому
маршруту. Выключение авто-переключения закрывает соединения, которые детектор пустил напрямую.

В каждом списке можно смешивать сайты (`example.com`, `+.example.com` — домен и всё под ним), адреса и
сети (`1.2.3.4`, `192.168.0.0/16`) и программы (`telegram.exe` или полный путь к одной копии). Имя на
своём языке (`госуслуги.рф`) записывается так, как его видит ядро, — в punycode. Адрес действует на
соединения, которые идут прямо по адресу: браузер ходит к сайтам по именам, поэтому сайт добавляйте
именем. Попытки, которые отклонил список «Запрещено», видны в Live на отдельной вкладке. Пока выбрано
«Только в туннель», «Всегда напрямую» отложен — страница списков об этом предупреждает.

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
  оставляют в покое, а через десять дней забывают. Если его срок уже вышел, на странице «Вердикты»
  у него написано «при следующем обращении».

### Домены целиком

Когда у домена 3 и больше чистых поддоменов и ни одного заблокированного, медленного или не
работающего напрямую, напрямую идёт весь домен (`+.example.com`): новые поддомены не ждут проверки
и проверяются уже потом. Первый плохой поддомен снимает правило. Помогает сервисам с пулом серверов:
CDN, спидтестам, обновлениям.

### Авто-переключение: вкл, «только наблюдать», «только в туннель»

Детектор проверяет сайты и записывает вердикты во всех трёх режимах, режимы отличаются только тем,
куда идёт трафик.

- **Вкл**: вердикты применяются. Незаблокированные сайты идут напрямую, остальное по спискам и в
  туннель.
- **Только наблюдать**: чистый директ — белый список. Всё идёт напрямую, кроме списков, которые работают
  как в любом режиме. Второй туннель при каждом выборе этого режима
  выключается; включите его на его странице, и пресеты и свой список awg2 тоже пойдут в awg2. Детектор
  проверяет всё, что идёт напрямую.
- **Только в туннель**: жёсткий режим. Всё, кроме «Всегда напрямую», идёт через туннели и никогда
  напрямую: если туннели лежат, соединения не проходят. «Всегда напрямую» — единственный выход мимо туннелей.

Локальная сеть и адреса самих туннелей идут напрямую, а список «Запрещено» отклоняется в любом
режиме. Переключение применяется за секунду: открытые соединения, которым режим меняет маршрут,
закрываются, и программы переподключаются по-новому. Вердикты сохраняются во всех режимах.

Переключатель второго туннеля («Использовать второй туннель») запоминается для каждого режима:
выключенный во «Вкл», он снова выключен при каждом выборе «Вкл», и так же для «Только в туннель».
Выключенный, его пресеты и список ничего не маршрутизируют.

### Сети

Вердикты хранятся по провайдеру (его номеру AS): другая сеть того же провайдера
пользуется ими же, другой провайдер начинает свои. Без сети проверки встают на паузу, память
сохраняется.

### DNS

- **Прямые сайты** резолвятся DNS для прямых сайтов, мимо туннеля: CDN отвечают узлами рядом с вашим
  провайдером. Детектор пользуется теми же серверами, так что проверяет тот узел, куда пойдёт трафик.
  Надёжнее всего DoH или DoT по адресу (`https://IP/dns-query`, `tls://IP`): многие провайдеры
  блокируют или подменяют обычный DNS. Кнопка «Проверить» в настройках опрашивает каждый сервер.
- **Сайты через туннель** резолвятся внутри того туннеля, через который идут, его собственным DNS: у awg1 и awg2 они задаются отдельно, каждый — из своего `.conf`, если не задан свой. Если в `.conf` нет `DNS =` и ничего не задано, имена резолвятся DNS для прямых сайтов, мимо туннеля.
- Программы получают от ядра подставные адреса (fake-ip: `198.18.0.0/16`, `2001:2::/48`), а настоящий
  ядро узнаёт уже на выбранном маршруте. Поэтому маршрут решает имя, а не адрес. Диапазон IPv6
  намеренно не ULA: Chrome считает `fc00::/7` локальной сетью и блокирует запросы к ней (Local Network
  Access).

> [!NOTE]
> Сохранение DNS перезапускает ядро: туннель пропадает на пару секунд.

### IPv6

С включённым IPv6 у компьютера есть IPv6, даже если у провайдера его нет: он идёт через туннель.
Прямые сайты ходят по IPv4. Если у сервера туннеля IPv6 не работает, программа это замечает и
резолвит для него только IPv4: ядро один раз перезапускается, и этот вывод держится сутки, потом
проверяется снова. Переключение перезапускает ядро.

### Второй туннель

Второй сервер AmneziaWG только для выбранных сервисов: YouTube, Telegram, ИИ-сервисов (ChatGPT,
Claude, Gemini, Grok, Copilot, DeepL и др.), Instagram, Facebook, X и вашего списка. Он стоит ниже
«Запрещено», «Всегда через туннель» и «Всегда напрямую» и выше детектора — детектор его имена не трогает.
Если он лежит, его сайты идут через первый туннель; если лежат оба — напрямую, а в «Только в туннель»
отклоняются. Детектор сравнивает прямой путь только с первым туннелем: то, что идёт в awg2, не проверяется никогда, а без awg1 не проверяется ничего, даже при включённом «Вкл». Пока он не подключён, пресеты
и свой список ничего не маршрутизируют. Все
пресеты по умолчанию выключены. Переключение пресета применяется сразу, включая открытые соединения.

Пресеты можно менять: **Изменить** открывает во всплывающем окне название, описание и строки пресета
(сайты, адреса, программы — как в списках; `#` — комментарий), **Удалить** убирает его, **Добавить…**
создаёт новый — он сразу включён. Всё это применяется так же сразу, без перезапуска ядра. Пока вы ничего
не меняли, используются пресеты программы.

Когда встроенный пресет удалён или изменён, появляется кнопка **Вернуть встроенные пресеты…**: она
возвращает их в том виде, в каком их поставляет программа. Удалённые возвращаются выключенными,
изменённые теряют ваши правки, ваши собственные пресеты остаются. Если своих пресетов нет, программа
снова следует своим пресетам, включая обновлённые списки новых версий.

### Live

Соединения, которые держит ядро, обновляются раз в секунду: программа, хост, адрес, порт, тип, маршрут,
скорость и объём в обе стороны. Цвет строки — маршрут: зелёный — напрямую, голубой — первый туннель,
сиреневый — второй, серый — проверки детектора. Наведите на маршрут, чтобы увидеть группу и правило,
которое его выбрало. Тип (TLS, QUIC, HTTP) определяется по порту, и метка у него пунктирная; если ядро
прочитало имя сайта из самого трафика, протокол подтверждён, и метка сплошная.

- **Вкладки.** «Открытые», «Закрытые», «Ошибки» (ядро не смогло соединиться: тайм-аут, отказ, сброс, имя
  не найдено…), «Запрещено» (попытки, которые отклонил список «Запрещено») и «Все». Та же ошибка той же
  программы к тому же адресу тем же маршрутом, по тому же правилу и по той же причине — не новая строка,
  а «×N» на прежней. Фильтр по хосту,
  программе и адресу, по маршруту и галка «Скрыть проверки детектора».
- **История.** Программа опрашивает ядро раз в секунду с запуска трея, открыта страница или нет. Закрытые
  соединения и ошибки хранятся весь запуск ядра, сколько бы времени ни прошло, — последние 100 000 каждого
  вида. Когда ядро запускается заново, история начинается сначала: служба помечает каждый запуск ядра, так
  что перезапуск виден, даже если он случился между двумя опросами. «Очистить» убирает закрытые и ошибки на
  всех открытых страницах. История живёт в памяти трея и при его перезапуске собирается заново. Соединение,
  которое открылось и закрылось быстрее секунды, может не попасть в таблицу.
- **Пауза** останавливает таблицу, а не сбор: закрытое и не удавшееся за это время появится, когда вы
  продолжите. Страница в фоне ничего не получает, а вернувшись, берёт только пропущенное.
- **Щелчок по строке** выделяет её и закрепляет на месте: при сортировке по скорости остальные строки
  двигаются вокруг неё, а закрывшееся соединение остаётся на своём месте, уже закрытым. Щелчок в любом
  другом месте, смена вкладки, фильтра или сортировки снимает выделение. **✕** в строке закрывает
  соединение в ядре: программа переподключится, и новое соединение пойдёт по текущим правилам.
- **Правый щелчок по строке** открывает меню. Сверху — что отправить: весь домен (`+.example.com`),
  только это имя, адрес (у соединения без имени — список направляет по адресу только такие) или программу.
  Ниже — куда: **Напрямую**, **В туннель**, **Во второй туннель**
  (его свой список), **В пресет** (выключенные пресеты приглушены: пока пресет выключен, он ничего не
  направляет), **Запретить**. **Расположение файла** открывает папку программы с выделенным файлом.

Строка из меню попадает в выбранный список, а открытые соединения, которых это касается, сразу
переносятся. Чтобы она действительно пошла выбранным путём, меню убирает её оттуда, где правила
сработали бы раньше. Правила ядра проверяются в таком порядке:

1. «Запрещено»;
2. «Всегда через туннель»;
3. «Всегда напрямую»;
4. второй туннель: включённые пресеты, затем его свой список;
5. вердикты детектора.

Из списков, чьи правила стоят **раньше** выбранного, убираются все строки, которые её направляют, в том
числе более широкие: `+.example.com` для `api.example.com`, `10.0.0.0/8` для адреса из этой сети,
программа по имени для её копии по пути. Широкая строка убирается целиком — исключение для одного имени в
списке не записать, — поэтому в ответе перечислено, что и откуда убрано. Из списков, чьи правила стоят
**позже**, убираются только та же строка и более узкие: более широкая там ничему не мешает. Пресеты стоят ниже
всех списков, поэтому строка, отправленная в список, их не меняет, а строка, отправленная в пресет,
убирается из списков. Списки и
пресеты меняются одной операцией: если какой-то файл не записался, уже записанные возвращаются как были.

### Если сайт не открывается

1. Найдите его фильтром на странице **Вердикты**. Если он идёт напрямую, а не должен, добавьте его во
   **Всегда через туннель** (`+.example.com` — весь домен). Правый клик по строке отправляет его в список
   сразу, как на Live; ✕ в строке сбрасывает один вердикт: сайт идёт через туннель, пока детектор не
   проверит его заново.
2. Если сломалось сразу много сайтов (провайдер ввёл новую блокировку), **сбросьте все вердикты** —
   на странице «Вердикты» или пунктом трея «Всё через туннель»: всё пойдёт через туннель, и детектор
   начнёт заново.
3. Если сайт должен видеть ваш настоящий адрес (банк, госуслуги), добавьте его во **Всегда напрямую**.
4. В **логах** виден каждый вердикт с причиной.
5. На странице **Live** видно, каким маршрутом и по какому правилу идут его соединения прямо сейчас, а
   правым щелчком по строке сайт можно сразу отправить в нужный список.

### Права и файлы

Служба принадлежит пользователю, который её установил: только он (и администраторы) может запускать
и останавливать её и менять настройки, списки и конфиги. Остальные учётные записи на компьютере видят
только её состояние.

- `%ProgramFiles%\DPI Switch` — программа; служба и трей запускаются отсюда.
- `%ProgramFiles%\DPI Switch\core\mihomo.exe` — ядро, которое служба распаковывает из себя; перед
  каждым запуском сверяется SHA-256, при несовпадении распаковывается заново. Оно лежит рядом с
  программой, а не в папке данных: там ядро само создаёт файлы, которые называет его конфиг.
- `%ProgramData%\dpiswitch` — данные службы: конфиг ядра, вердикты (`controller-state.json`), каждая
  проба (`reports.jsonl`), логи (`logs\service.log`, `logs\mihomo.log`), метка запуска ядра, по
  которой Live узнаёт новый запуск (`core-run.txt`). Писать туда могут только SYSTEM и администраторы,
  читать — ещё вы: лог ядра и пробы называют каждый сайт, куда ходит компьютер, и другим учётным
  записям их видеть незачем.
- `%ProgramData%\dpiswitch\user` — то, что вы меняете в интерфейсе: `.conf`, списки, настройки.
  Писать туда можете только вы; служба это читает и никогда туда не пишет. Файлы с приватными
  ключами читаете только вы и служба.
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
переиспользуется, пока отметка `dist\mihomo.commit` совпадает с закреплённым коммитом. Ядро собирается
из форка mihomo [chesnokovap10/mihomo-dpiswitch](https://github.com/chesnokovap10/mihomo-dpiswitch) на
закреплённом коммите: проверенная альфа mihomo, все зависимости в `vendor/` и правки для DPI Switch —
первые пакеты через WireGuard не теряются после старта, API ядра оставляет только то, что вызывает
служба, а слушатели пробника пускают только его самого, UDP тоже. Оставлено только нужное DPI Switch: исходящий WireGuard (AmneziaWG), входящие TUN и SOCKS;
остальные протоколы, gVisor, встроенные Tailscale, ZeroTier и EasyTier и отладочные символы выброшены:
~30 МБ вместо ~80 МБ. TUN работает на сетевом стеке Windows (`stack: system`).

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
`go test -race` (`.\build.ps1` сам гоняет vet и тесты перед сборкой и не собирает, если они не прошли).

Маршрутизация проверяется отдельно, по таблицам из справки — каждый режим, каждый набор загруженных
конфигов, каждый список, с туннелями, падающими по очереди: `go test -tags routing ./internal/awgconf`.
Обычный `go test` эти проверки пропускает; запускайте их всякий раз, когда меняете правила, группы,
файлы списков или режимы.

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
- [Auto-switch: on, observe only, tunnel only](#auto-switch-on-observe-only-tunnel-only)
- [Networks](#networks)
- [DNS](#dns-1)
- [IPv6](#ipv6-1)
- [The second tunnel](#the-second-tunnel)
- [Live](#live-1)
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
| **Verdicts** | Every verdict in the "Direct", "Blocked", "Slower", "Unverified" tabs, a name filter (names in Russian letters are found and shown as written); a click pins a row, a right-click sends it to a list, ✕ resets its verdict; "Reset all verdicts…" |
| **Routing lists** | "Always direct", "Always via tunnel", "Forbidden": sites, addresses and programs in each |
| **Second tunnel** | Attaching awg2, presets (YouTube, Telegram, AI services, Instagram/Facebook/X; edit them, delete them, add your own) and your own list |
| **Settings** | Detector, terms, IPv6, DNS; every change applies at once |
| **Logs** | The controller and service log, the core's, the tray and UI's; the last 400 lines, the previous file's included after a rotation |
| **Help** | What is described below; its links lead straight to the field meant, which blinks |
| **Live** | The core's connections every second — open, closed, failed and forbidden tries over the core's whole run; a click pins a row, a right-click sends its site, address or program to a list. More in [Live](#live-1) |

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
| Auto-switch | On | Unblocked sites go direct; "Observe only" — everything direct but the lists (a whitelist); "Tunnel only" — everything but Always direct through the tunnels and never direct. Verdicts are recorded in every mode |
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
| 3 | Forbidden: programs, sites, addresses | refused, in every mode |
| 4 | Local networks: the router, printers, shares, `.local` and `.lan` names | direct |
| 5 | Always via tunnel: programs, sites, addresses | awg1; if it is down, awg2 while switched on; never direct |
| 6 | Always direct: programs (`qbittorrent.exe`, etc.), sites, addresses | direct, in every mode |
| 7 | Second tunnel, while loaded and switched on: presets and your list | awg2; if it is down, awg1; then direct — in Tunnel only refused |
| 8 | Everything else, while "Observe only" is chosen | direct |
| 9 | Detector verdicts: names found clean, and the addresses they were probed on (for connections that carry no name) | direct |
| 10 | Everything else | by the mode: in On awg1, then awg2 (if switched on), then direct; in Tunnel only the same tunnels, never direct |

Without the first tunnel's config the service runs all the same: Live shows the traffic, the lists apply,
and the detector checks nothing, having no tunnel to compare with. The second tunnel, loaded alone, takes
its presets and list and Always via tunnel -- in Tunnel only, everything. The program's help has a table
for each mode and each set of configs loaded.

A line written in several lists goes by the one higher in the table: Forbidden → Always via tunnel →
Always direct → the presets and the awg2 list → the detector.

The core decides once, when a connection opens. When you change a list or a preset, the open
connections the change moves are closed, and the programs reconnect over the new route. Turning
auto-switch off closes the connections the detector sent direct.

Every list takes sites (`example.com`, `+.example.com` for the domain and all under it), addresses and
networks (`1.2.3.4`, `192.168.0.0/16`) and programs (`telegram.exe`, or a full path for one copy) in
any mix. A name in its own letters (`госуслуги.рф`) is written as the core sees it, in punycode. An
address counts for connections made to it by address: a browser reaches sites by name, so add a site
by its name. The tries the Forbidden list refuses show on a tab of their own in Live. While "Tunnel
only" is chosen, Always direct is set aside — the lists page says so.

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
  left alone, and after ten days it is forgotten. If its term is over, the Verdicts page says "when
  next used" for it.

### Whole domains

When a domain has 3 or more clean subdomains and none blocked, slower or failing directly, the whole
domain (`+.example.com`) goes direct: new subdomains do not wait for a check and are verified
afterwards. The first bad subdomain removes the rule. It helps services with pools of servers: CDNs,
speed tests, updates.

### Auto-switch: on, observe only, tunnel only

The detector checks sites and records verdicts in all three modes; the modes differ only in where the
traffic goes.

- **On**: the verdicts are applied. Unblocked sites go direct, the rest by the lists and through the
  tunnel.
- **Observe only**: plain direct — a whitelist. Everything goes direct but the lists, which go their way
  as in every mode. The second tunnel starts switched off each time this
  mode is chosen; switch it on on its page, and its presets and list go to awg2 too. The detector checks
  everything that goes direct.
- **Tunnel only**: a strict mode. Everything but "Always direct" goes through the tunnels and never
  direct: with the tunnels down it fails. "Always direct" is the one way out past the tunnels.

The local network and the tunnels' own addresses go direct, and the Forbidden list is refused, in
every mode. Switching applies within a
second: the open connections the mode sends another way are closed, and the programs reconnect the new
way. The verdicts are kept in every mode.

The second tunnel's switch ("Use the second tunnel") is kept per mode: switched off in On, it is off
again whenever On is chosen, and so for Tunnel only. Switched off, its presets and list route nothing.

### Networks

Verdicts are kept per ISP (its AS number): another network of the same ISP
shares them, another ISP starts its own. Without a network the checks pause and the memory is kept.

### DNS

- **Direct sites** are resolved by the resolvers for direct sites, asked outside the tunnel: CDNs
  then answer with nodes near your ISP. The detector uses the same resolvers, so it tests the node
  the traffic will go to. DoH or DoT by address (`https://IP/dns-query`, `tls://IP`) is the safe
  choice: many ISPs block or tamper with plain DNS. The "Test" button in the settings asks each
  server.
- **Tunnelled sites** are resolved inside the tunnel they go through, by that tunnel's own DNS: awg1's and awg2's are set apart, each from its `.conf` unless set. A `.conf` with no `DNS =` and nothing set: the names are resolved by the resolvers for direct sites, outside the tunnel.
- Programs get stand-in addresses from the core (fake-ip: `198.18.0.0/16`, `2001:2::/48`) and the
  core resolves the real one on the chosen route. That is why a name, not an address, decides the
  route. The IPv6 range is deliberately not ULA: Chrome treats `fc00::/7` as a local network and
  blocks requests to it (Local Network Access).

> [!NOTE]
> Saving the DNS restarts the core: the tunnel drops for a couple of seconds.

### IPv6

With IPv6 on, the computer gets IPv6 even where the ISP has none: it goes through the tunnel. Sites
going direct use IPv4. If the tunnel's server has no working IPv6, the program finds out and
resolves IPv4 only for it: the core restarts once, and that finding holds for a day before it is
checked again. Changing it restarts the core.

### The second tunnel

A second AmneziaWG server for chosen services only: YouTube, Telegram, AI services (ChatGPT, Claude,
Gemini, Grok, Copilot, DeepL and more), Instagram, Facebook, X and your own list. It stands below
Forbidden, Always via tunnel and Always direct and above the detector, which leaves its names alone. If it
is down, its sites go through the first tunnel; if both are down, direct — in Tunnel only refused. The detector measures the direct path against the first tunnel only: what goes to awg2 is never checked, and without awg1 nothing is, even with auto-switch On. Until it is attached, its presets and list route
nothing. Every
preset is off by default. A preset switch applies at once, open connections included.

The presets are yours to change: **Edit** opens a preset's name, description and lines in a dialog
(sites, addresses and programs, as in the lists; `#` starts a comment), **Delete** removes it,
**Add…** makes a new one, switched on at once. These apply at once too, with no core restart. Until
you change any, the program's own presets are used.

Once a built-in preset is deleted or edited, **Restore built-in presets…** appears: it puts them back
as the program ships them. The deleted ones come back switched off, the edited ones lose your
changes, and your own presets stay. With none of your own, the program follows its presets again,
the updated lists of new versions included.

### Live

The connections the core holds, refreshed every second: the program, the host, the address, the port,
the type, the route, the speed and the bytes both ways. A row's colour is its route: green direct, blue
the first tunnel, violet the second, grey the detector's checks. Hover over a route for the group and
the rule that chose it. The type (TLS, QUIC, HTTP) is told by the port, with a dashed badge; where the
core read the site's name from the traffic itself the protocol is confirmed, and the badge is solid.

- **Tabs.** Open, Closed, Failed (the core could not connect: timed out, refused, reset, name not
  found…), Forbidden (the tries the Forbidden list refused) and All. The same failure of the same
  program to the same address by the same route and rule, for the same reason, is no new row but "×N"
  on the old one. A filter by
  host, program and address, one by route, and "Hide the detector's checks".
- **History.** The program asks the core every second from the tray's start, whether the page is open
  or not. The closed connections and the failures are kept for the core's whole run, however old: the
  last 100,000 of each. When the core starts anew the history starts over: the service names every run
  of the core it starts, so a restart shows even between two calls. Clear removes the closed ones and
  the failures on every page open. The history lives in the tray's memory and is gathered anew when the
  tray restarts. A connection that opened and closed within a second may never show.
- **Pause** stops the table, not the gathering: what closes and fails meanwhile is there when you
  resume. A page in the background takes nothing, and coming back takes only what it missed.
- **A row clicked** is picked and holds its place: sorted by speed, the others move around it, and a
  connection that closes stays where it was, closed. A click anywhere else, or a change of tab, filter or
  sort, lets it go. **✕** in a row closes the connection in the core: the program reconnects, and the
  new connection follows the rules as they are now.
- **A row right-clicked** opens a menu. On top, what to send: the whole domain (`+.example.com`), the
  name alone, the address (of a connection with no name: a list routes such ones only by address) or the
  program. Then where: **Direct**, **Via the tunnel**, **Via the second
  tunnel** (its own list), **To a preset** (the ones off are greyed: a preset switched off routes
  nothing), **Forbid**. **File location** opens the program's folder with its file picked out.

A line sent from the menu goes to the list chosen, and the open connections it moves are moved at once.
For it to take that route, the menu takes it out of wherever a rule would route it first. The core's
rules come in this order:

1. Forbidden;
2. Always via tunnel;
3. Always direct;
4. the second tunnel: its presets switched on, then its own list;
5. the detector's verdicts.

A list whose rules come **before** the one chosen loses every line routing it, a wider one too:
`+.example.com` for `api.example.com`, `10.0.0.0/8` for an address in it, a program by its name for a
copy of it by its path. A wider line goes whole — a list cannot hold an exception for one name — so the
answer names what went, and from where. A list whose rules come **after** it loses the same line and the
narrower ones only: a wider line there is in nobody's way. The presets stand below every list: a line
sent to a list leaves them as they are, and a line sent to a preset is taken out of the lists. The lists
and the presets change as one: a file failing to write puts back the ones written before it.

### When a site does not open

1. Look it up on the **Verdicts** page with the filter. If it goes direct and should not, add it to
   **Always via tunnel** (`+.example.com` for the whole domain). A right-click on its row sends it to a
   list straight away, as on Live; the ✕ in the row resets that one verdict: the site goes through the
   tunnel until the detector checks it again.
2. If many sites broke at once (a new block by the ISP), **reset all verdicts** — on the Verdicts
   page or with the tray's "Everything via tunnel": everything goes through the tunnel and the
   detector starts over.
3. If a site must see your real address (a bank, government services), add it to **Always direct**.
4. The **logs** show every verdict with its reason.
5. The **Live** page shows which route its connections take right now, and by which rule; a
   right-click on a row sends the site straight to the list it belongs in.

### Permissions and files

The service belongs to the user who installed it: only that user (and administrators) may start and
stop it and change its settings, lists and configs. Other accounts on the machine may only see its
state.

- `%ProgramFiles%\DPI Switch` — the program; the service and the tray run from here.
- `%ProgramFiles%\DPI Switch\core\mihomo.exe` — the core, which the service extracts from itself;
  its SHA-256 is verified before every start, and it is re-extracted if it does not match. It sits
  beside the program, not in the data directory: there the core makes the files its config names.
- `%ProgramData%\dpiswitch` — the service's own data: the core's config, the verdicts
  (`controller-state.json`), every probe (`reports.jsonl`), the logs (`logs\service.log`,
  `logs\mihomo.log`), the name of the core's run Live tells a new run by (`core-run.txt`). Writable by
  SYSTEM and Administrators only, readable by you as well: the core's log and the probes name every
  site the computer goes to, and other accounts have no business seeing them.
- `%ProgramData%\dpiswitch\user` — what you change in the UI: the `.conf` files, lists, settings.
  Writable by you alone; the service reads it and never writes there. Files holding private keys are
  readable by you and the service only.
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
`dist\mihomo.exe` and reused afterwards, while its stamp `dist\mihomo.commit` names the pinned commit.
The core is built from the fork of mihomo at
[chesnokovap10/mihomo-dpiswitch](https://github.com/chesnokovap10/mihomo-dpiswitch), at a pinned
commit: the tested mihomo Alpha, every dependency in `vendor/` and changes for DPI Switch -- the first
packets through WireGuard are not lost after a start, the core's API keeps only what the service calls,
and the prober's listeners take the prober alone, UDP included. Only what DPI Switch uses is kept: the WireGuard outbound (AmneziaWG) and the
TUN and SOCKS inbounds; every other protocol, gVisor, the embedded Tailscale, ZeroTier and EasyTier and
the debug symbols are left out: ~30 MB instead of ~80 MB. The TUN runs on the Windows network stack
(`stack: system`).

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
`go test -race` (`.\build.ps1` runs vet and the tests itself before building, and stops if they fail).

Routing has checks of its own, by the tables of the help -- every mode, every set of configs loaded,
every list, with the tunnels going down one after the other: `go test -tags routing ./internal/awgconf`.
A plain `go test` leaves them out; run them whenever the rules, the groups, the lists' files or the modes
change.

<p align="right"><a href="#readme">↑ back to top</a> · <a href="#русский">Русский</a></p>
