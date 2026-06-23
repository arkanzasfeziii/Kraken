# Contributing to Kraken

## Setup

```bash
git clone https://github.com/arkanzasfeziii/Kraken.git
cd Kraken
pip install -r requirements.txt
pip install ruff pytest
make test
```

## Adding a New Module

1. Create `kraken/modules/your_module.py` extending `BaseModule`
2. Implement `run(ctx, **kwargs) -> List[AttackResult]`
3. Register in `kraken/cli.py: MODULE_REGISTRY`
4. Update `kraken/modules/__init__.py`
5. Add tests

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/).
