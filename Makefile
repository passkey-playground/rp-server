.PHONY: dev test lint

dev:
	./gradlew bootRun

test:
	./gradlew test

lint:
	./gradlew check
