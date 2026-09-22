// Пресеты второго туннеля: наборы сервисов, которые всегда идут через
// awg2 (выход vpsde), минуя детектор.
//
// Списки сняты с серверов пользователя, где та же задача уже решена
// на стороне VPS:
//   - AI: SNI-белый список nginx на vpsde (/etc/nginx/dot-allow.conf)
//     и зоны Google AI из unbound на vpsru (/etc/unbound/forward/zones.txt);
//   - Telegram: диапазоны core.telegram.org/resources/cidr.txt из кэша
//     relay-routes.sh на vpsru, плюс домены;
//   - YouTube: домены (сервер шлёт весь Google по goog.json, клиенту
//     достаточно YouTube).
//
// Каждый пресет -- отдельный rule-provider с постоянным файлом. Выключенный
// пресет пишется пустым: ядро следит за файлами само, и включение или
// выключение не требует ни перезапуска, ни правки config.yaml.
package presets

import (
	"bufio"
	"embed"
	"fmt"
	"net"
	"os"
	"strings"

	"dpiswitch/internal/paths"
)

//go:embed lists/*.txt
var lists embed.FS

type Preset struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Note  string `json:"note"`
	files []string
}

var All = []Preset{
	{ID: "youtube", Title: "YouTube", Note: "сайт, видео, превью, приложения",
		files: []string{"youtube.txt"}},
	{ID: "telegram", Title: "Telegram", Note: "домены и сети Telegram — приложение ходит по IP",
		files: []string{"telegram-domains.txt", "telegram-cidr.txt"}},
	{ID: "ai", Title: "AI-сервисы", Note: "ChatGPT, Claude, Gemini, Grok, Copilot, DeepL и др.",
		files: []string{"ai-sni.txt", "ai-google.txt"}},
}

func Valid(id string) bool {
	for _, p := range All {
		if p.ID == id {
			return true
		}
	}
	return false
}

// Rules: классические правила mihomo для пресета.
// Домен -> DOMAIN-SUFFIX (покрывает поддомены), "*.домен" -> тоже суффикс,
// сеть -> IP-CIDR/IP-CIDR6 с no-resolve: правило срабатывает только на
// соединения по голому IP и не заставляет резолвить каждый домен.
func (p Preset) Rules() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range p.files {
		b, err := lists.ReadFile("lists/" + f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			var r string
			if _, n, err := net.ParseCIDR(l); err == nil {
				if n.IP.To4() != nil {
					r = "IP-CIDR," + n.String() + ",no-resolve"
				} else {
					r = "IP-CIDR6," + n.String() + ",no-resolve"
				}
			} else {
				r = "DOMAIN-SUFFIX," + strings.ToLower(strings.TrimPrefix(l, "*."))
			}
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}

// Write раскладывает пресеты по файлам: включённые -- правилами,
// выключенные -- пустыми.
func Write(enabled []string) error {
	on := map[string]bool{}
	for _, id := range enabled {
		on[id] = true
	}
	for _, p := range All {
		var b strings.Builder
		fmt.Fprintf(&b, "# пресет %s -- генерируется программой, руками не править\n", p.ID)
		if on[p.ID] {
			for _, r := range p.Rules() {
				b.WriteString(r + "\n")
			}
		} else {
			b.WriteString("# выключен\n")
		}
		path := paths.Preset(p.ID)
		if old, err := os.ReadFile(path); err == nil && string(old) == b.String() {
			continue // без лишней записи: ядро перечитывает файл при каждом изменении
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	return nil
}
