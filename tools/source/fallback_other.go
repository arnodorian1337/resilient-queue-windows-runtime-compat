//go:build !windows

package main

func fallbackLanguageServerCandidates(rec *recorder) []candidate {
	rec.line("ADDRESS source=process-table present=false")
	return nil
}
