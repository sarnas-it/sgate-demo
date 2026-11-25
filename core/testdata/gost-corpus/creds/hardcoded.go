package creds

// Password захардкожен в исходном коде.
const Password = "Sup3rSecret!" // GOST:6.3г CWE-798

// Login возвращает пароль для подключения.
func Login() string {
	return Password
}
