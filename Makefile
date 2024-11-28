
project:=SwiftNcal
comma:=,

format:
    swiftformat --config .swiftformat Sources/ Tests/

lint: make-test-results-dir
    - swiftlint lint --reporter html > TestResults/lint.html

view_lint: lint
    open TestResults/lint.html

generate-docs: doc-symbol-graphs
    swift package --allow-writing-to-directory .build/docs generate-documentation --enable-inherited-docs --additional-symbol-graph-dir .build/symbol-graphs --target PotentCodables --output-path .build/docs --transform-for-static-hosting --hosting-base-path PotentCodable

preview-docs: doc-symbol-graphs
    swift package --disable-sandbox preview-documentation --enable-inherited-docs --additional-symbol-graph-dir .build/symbol-graphs --target PotentCodables

changelog: ## Update changelog
	cz ch

bump: ## Bump version according to changelog
	cz bump
