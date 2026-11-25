// Фикстура для проверки правил SGATE. Аннотация в конце строки задаёт
// ожидание: ruleid — находка обязана быть, ok — обязана отсутствовать.
// Проверка: scripts/check-rules.sh.
package fixtures

import (
	"os/exec"
)

func commandInjection(cmd string) {
	exec.Command("sh", "-c", cmd) // ruleid: sgate-go-command-injection
	exec.Command("git", "status") // ok: sgate-go-command-injection
}

func hardcodedCredentials() {
	const password = "Sup3rS3cretValue" // ruleid: sgate-go-hardcoded-credentials
	const passwordMask = "********"     // ok: sgate-go-hardcoded-credentials
	const host = "example.internal"     // ok: sgate-go-hardcoded-credentials
	_ = password
	_ = passwordMask
	_ = host
}
