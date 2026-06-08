deploys

we deploy from main. ci runs tests + lint, builds the container, pushes to the
registry, then argocd syncs. rollbacks: re-point argocd to previous image tag.
hotfixes go on a hotfix/ branch, still through ci, no direct pushes to prod.
on-call owns the deploy if it's after hours. prod creds are in vault, never in
env files.
