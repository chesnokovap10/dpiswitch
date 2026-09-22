package paths

import (
	"dpiswitch/internal/winexec"
	"fmt"
	"os/user"
)

// Restrict закрывает файл: снимает наследование и оставляет доступ
// только системе, администраторам и текущему пользователю.
//
// Права задаются по SID, а не по именам групп: на локализованной
// Windows "Administrators" называется иначе, и по имени не найдётся.
//
// Честная оговорка: это защищает ключ от ДРУГИХ непривилегированных
// учёток на машине. От администратора и от процессов под твоей же
// учёткой не защищает -- для этого нужно шифрование, а ключ всё равно
// должен быть доступен ядру в открытом виде.
func Restrict(path string) error {
	grants := []string{
		"*S-1-5-18:(F)",     // NT AUTHORITY\SYSTEM -- под ней работает служба
		"*S-1-5-32-544:(F)", // BUILTIN\Administrators
	}
	if u, err := user.Current(); err == nil && u.Uid != "" {
		grants = append(grants, "*"+u.Uid+":(F)") // чтобы трей мог перезаписать конфиг
	}
	args := append([]string{path, "/inheritance:r"}, prefix("/grant:r", grants)...)
	if out, err := winexec.CombinedOutput("icacls.exe", args...); err != nil {
		return fmt.Errorf("icacls: %v (%s)", err, out)
	}
	return nil
}

func prefix(flag string, items []string) []string {
	out := make([]string, 0, len(items)*2)
	for _, i := range items {
		out = append(out, flag, i)
	}
	return out
}

// GrantUsersModify выдаёт интерактивным пользователям право изменять
// файлы в каталоге данных, с наследованием на создаваемые файлы.
//
// Нужно потому, что служба работает от SYSTEM: созданные ею файлы
// (состояние, список вердиктов) достаются пользователю только на чтение.
// Без этого трей не может ни сбросить вердикты аварийной кнопкой,
// ни поправить списки -- отказ происходит молча, в самый неподходящий момент.
//
// Конфиг с приватным ключом это не затрагивает: у него наследование
// снято отдельным вызовом Restrict.
func GrantUsersModify(dir string) error {
	// S-1-5-32-545 -- BUILTIN\Users; (OI)(CI) -- наследование на файлы
	// и подкаталоги; (M) -- изменение без смены прав
	if out, err := winexec.CombinedOutput("icacls.exe", dir,
		"/grant", "*S-1-5-32-545:(OI)(CI)(M)", "/T", "/C"); err != nil {
		return fmt.Errorf("icacls: %v (%s)", err, out)
	}
	return nil
}
