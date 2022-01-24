# Git

## Commit Pattern

Commit message template: 
```
<type>: <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

Use the following **type** for your commit messages: 

* `docs: ` for commit related to **documentation** change
* `feat: ` for commit related to a new feature, also add a reference to the Github issue in the **subject** 
* `fix: `  for commit related to a bug fix, also add a reference to the Github issue in the **subject**

Use the following **type** for commits that should not appear in changelog or release note uses: 

* `test:` for test 
* `typo:` for fixing typo 
* `ignore:` for everything else


### Breaking Change or Note

Mention `BREAKING CHANGE:` or `NOTE:`  in the **footer**.


## Use rebase before submitting Pull Request

Make sure to rebase you commits (on your feature branch) first so that the git log follows the patterns mentioned above. 

```
git rebase -i
```





