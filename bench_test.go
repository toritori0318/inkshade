package main

import "testing"

func BenchmarkProcessMask(b *testing.B) {
	e := NewEngine(DefaultConfig())
	input := "contact tanaka@example.com call 090-1234-5678 card 4111111111111111 from 192.168.1.100"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Process(input)
	}
}

func BenchmarkProcessNoPII(b *testing.B) {
	e := NewEngine(DefaultConfig())
	input := "this is a normal log line with no personally identifiable information at all"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Process(input)
	}
}

func BenchmarkProcessPartialMask(b *testing.B) {
	cfg := DefaultConfig()
	cfg.MaskStyle = MaskStylePartial
	e := NewEngine(cfg)
	input := "contact tanaka@example.com call 090-1234-5678 card 4111111111111111"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Process(input)
	}
}

func BenchmarkProcessPseudo(b *testing.B) {
	cfg := DefaultConfig()
	cfg.MaskStyle = MaskStylePseudo
	e := NewEngine(cfg)
	input := "contact tanaka@example.com call 090-1234-5678 card 4111111111111111"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Process(input)
	}
}

func BenchmarkDetectOnly(b *testing.B) {
	e := NewEngine(DefaultConfig())
	input := "contact tanaka@example.com call 090-1234-5678 card 4111111111111111 from 192.168.1.100"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Detect(input)
	}
}

func BenchmarkJPStrictPreset(b *testing.B) {
	cfg := DefaultConfig()
	cfg.EnabledPreset = "jp-strict"
	e := NewEngine(cfg)
	input := "tanaka@example.com 123456789018 口座 1234567 090-1234-5678"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Process(input)
	}
}
