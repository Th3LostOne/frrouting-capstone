# Team Git workflow

The shared team repository is https://github.com/Th3LostOne/frrouting-capstone.

- `origin` points to the shared team repository.
- `upstream` points to the instructor's repository, https://github.com/pbrisset/frr.
- Develop and test on a personal development branch.
- Review and stage only the files intended for the change.
- Commit locally, then run `git push` to upload to the branch on `origin`.
- Open a pull request in the shared repository to merge into the team's agreed integration branch.

The branch `dev/vanshpatel.evpn_mobility` tracks
`origin/dev/vanshpatel.evpn_mobility`.
