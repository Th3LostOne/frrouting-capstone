# Team Git workflow

The shared team repository is https://github.com/Th3LostOne/frrouting-capstone.

- `origin` points to the shared team repository.
- `upstream` points to the instructor's repository, https://github.com/pbrisset/frr.
- The team's shared integration branch is `capstone`.
- Local `capstone` tracks `origin/capstone`.
- Pull shared changes before starting work, then edit and test locally.
- Review and stage only the files intended for the change, then commit locally.
- Commits remain local until an explicit push is requested.
- When ready to share, integrate any newer team commits and push to `origin capstone`.
- Never force-push the shared branch.
