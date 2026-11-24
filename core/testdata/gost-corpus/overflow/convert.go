package overflow

// Narrow сужает разрядность без проверки диапазона.
func Narrow(n int64) int32 {
	return int32(n) // GOST:6.3б CWE-190
}
