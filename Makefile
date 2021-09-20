
deps:
	go mod download

run-example:
	go run examples/dump_dcg_content.go

.PHONY: run-example deps
