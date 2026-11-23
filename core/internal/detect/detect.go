// Package detect определяет языки по расширениям файлов репозитория.
package detect

import (
	"io/fs"
	"path/filepath"
	"strings"
)

var extLanguage = map[string]string{
	".go":    "go",
	".php":   "php",
	".js":    "javascript",
	".jsx":   "javascript",
	".mjs":   "javascript",
	".cjs":   "javascript",
	".ts":    "typescript",
	".tsx":   "typescript",
	".py":    "python",
	".java":  "java",
	".rb":    "ruby",
	".rs":    "rust",
	".c":     "c",
	".h":     "c",
	".cc":    "cpp",
	".cpp":   "cpp",
	".hpp":   "cpp",
	".cs":    "csharp",
	".kt":    "kotlin",
	".kts":   "kotlin",
	".swift": "swift",
	".scala": "scala",
	".sh":    "bash",
}

var skipDirs = map[string]bool{
	".git": true, ".next": true, "node_modules": true, "vendor": true,
	"dist": true, "build": true, "target": true, ".venv": true,
	"__pycache__": true, ".tools": true, ".demo-out": true,
}

// Languages возвращает множество языков, найденных в repo.
func Languages(root string) (map[string]bool, error) {
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if lang, ok := extLanguage[ext]; ok {
			out[lang] = true
		}
		return nil
	})
	return out, err
}

// Select возвращает анализаторы, у которых есть общий язык с репозиторием.
func Select(analyzers []struct {
	ID        string
	Languages []string
}, langs map[string]bool) []string {
	var ids []string
	for _, a := range analyzers {
		for _, l := range a.Languages {
			if langs[strings.ToLower(l)] {
				ids = append(ids, a.ID)
				break
			}
		}
	}
	return ids
}
