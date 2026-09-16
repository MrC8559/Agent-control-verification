# Contributing

Contributions are welcome, especially reproducible cases where a control decision and a real observed effect disagree.

Before opening a large PR, open an issue describing the security property and evidence you want to add.

## A good contribution

A strong verification case contains:

1. a precise property;
2. a controlled environment;
3. a hardened case expected to PASS;
4. a vulnerable/mutated case expected to FAIL;
5. an explicit INCONCLUSIVE path when evidence is unavailable;
6. regression tests;
7. no real secrets or unauthorized targets.

Run:

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

Do not weaken a test merely to make CI green. If the environment cannot establish a security property, represent that uncertainty explicitly.
