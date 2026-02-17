# Memory Evaluation Golden Dataset

Human-annotated test cases for evaluating LLM-dependent memory behaviors.

## Structure

- `extraction/cases.json` — 35 cases testing fact extraction from conversations
- `arbitration/cases.json` — 20 cases testing memory conflict resolution
- `contradiction/cases.json` — 10 cases testing stale memory detection (full pipeline)

## Running

```bash
# Requires GEMINI_API_KEY and Docker (for contradiction tests)
go test -tags=evaluation -v -timeout=15m \
  -run "TestExtractionGolden|TestArbitrationGolden|TestContradictionGolden" \
  ./internal/memory/
```

## Adding Cases

1. Choose the appropriate category (extraction, arbitration, or contradiction)
2. Add a new entry to the JSON array with a unique ID (e.g., ext-036, arb-021, con-011)
3. Follow the schema documented in `eval_test.go`
4. For extraction cases: include both `want_facts` and `reject_facts`
5. For arbitration cases: include `accept_ops` for ambiguous decisions
6. Set `min_importance`/`max_importance` for at least half of extraction cases

## Scoring

- **Semantic match**: embedding cosine similarity >= 0.90 AND keyword Jaccard >= 0.30
- **Category**: exact string match
- **Importance**: within [min_importance, max_importance] range
- **Operation**: exact match against `want_operation` or any of `accept_ops`

## Thresholds

| Metric | Target |
|--------|--------|
| Extraction Precision | >= 0.85 |
| Extraction Recall | >= 0.80 |
| Reject Rate | >= 0.95 |
| Category Accuracy | >= 0.90 |
| Importance MAE | <= 1.5 |
| Arbitration Accuracy | >= 0.80 |
| Contradiction Detection | >= 0.75 |
