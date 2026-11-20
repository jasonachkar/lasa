#!/usr/bin/env bash
# Read-only inventory. Print selected metadata and explicit API failures.
set -euo pipefail
export GH_PROMPT_DISABLED=1
repo=jasonachkar/lasa
base="repos/$repo"
if [[ $(gh api --hostname github.com "$base" --jq '[.full_name,.visibility] | join(" ")') != "$repo private" ]]; then
  echo 'Expected the private LASA repository.' >&2
  exit 1
fi
inventory() {
  local endpoint=$1 query=$2 value error
  error=$(mktemp)
  if value=$(gh api --hostname github.com "$endpoint" --jq "$query" 2>"$error"); then
    printf '%s\t%s\n' "$endpoint" "${value:-HTTP success}"
  else
    printf '%s\tUNVERIFIED (%s)\n' "$endpoint" "$(sed -nE 's/.*\(HTTP ([0-9]{3})\).*/HTTP \1/p' "$error" | head -n 1)"
  fi
  rm -f "$error"
}
inventory "$base" '{full_name,visibility,private,default_branch,owner_type:.owner.type,permissions,allow_auto_merge,allow_squash_merge,allow_merge_commit,allow_rebase_merge,delete_branch_on_merge,security_and_analysis}'
inventory "$base/collaborators?per_page=100" '[.[]|{owner:(.login=="jasonachkar"),role_name}]'
inventory "$base/invitations?per_page=100" length
inventory "$base/rulesets?includes_parents=true" '[.[]|{id,name,enforcement,target,source_type}]'
ids=$(gh api --hostname github.com "$base/rulesets?includes_parents=true" --jq '.[].id')
for id in $ids; do
  [[ $id =~ ^[0-9]+$ ]] || exit 1
  inventory "$base/rulesets/$id" '{name,target,enforcement,bypass_actors,conditions,rules}'
done
inventory "$base/rules/branches/main" '[.[]|{type,parameters}]'
inventory "$base/branches/main/protection" '{enforce_admins,required_status_checks,required_pull_request_reviews}'
inventory "$base/actions/permissions" '{enabled,allowed_actions,sha_pinning_required}'
inventory "$base/actions/permissions/workflow" '.'
inventory "$base/actions/permissions/access" '{access_level}'
inventory "$base/actions/permissions/fork-pr-workflows-private-repos" '.'
inventory "$base/actions/permissions/fork-pr-contributor-approval" '.'
inventory "$base/actions/runners" '{total_count}'
inventory "$base/actions/workflows" '[.workflows[]|{name,path,state}]'
inventory "$base/environments" '[.environments[]|{name,deployment_branch_policy,protection:[.protection_rules[].type]}]'
inventory "$base/environments/release" '{can_admins_bypass,deployment_branch_policy,protection:[.protection_rules[].type]}'
inventory "$base/environments/release/deployment-branch-policies" '[.branch_policies[]|{name,type}]'
inventory "$base/environments/release/secrets" '[.secrets[].name]'
inventory "$base/environments/release/variables" '[.variables[].name]'
inventory "$base/actions/secrets" '[.secrets[].name]'
inventory "$base/actions/variables" '[.variables[].name]'
inventory "$base/dependabot/secrets" '[.secrets[].name]'
inventory "$base/keys?per_page=100" '[.[]|{read_only,verified}]'
inventory "$base/hooks?per_page=100" '[.[]|{active,events}]'
inventory "$base/installation" '{app_slug,repository_selection}'
inventory "$base/vulnerability-alerts" '.'
inventory "$base/automated-security-fixes" '{enabled,paused}'
inventory "$base/dependabot/alerts?state=open" '[.[]|{number,state,severity:.security_advisory.severity}]'
inventory "$base/secret-scanning/alerts?state=open" '[.[]|{number,state,secret_type}]'
inventory "$base/code-scanning/default-setup" '{state,languages,query_suite}'
inventory "$base/private-vulnerability-reporting" '{enabled}'
inventory "$base/immutable-releases" '{enabled,enforced_by_owner}'
inventory "$base/releases?per_page=100" '[.[]|{tag_name,draft,immutable,assets:[.assets[]|{name,digest}]}]'
inventory "$base/tags?per_page=100" '[.[].name]'
inventory "$base/pages" '{build_type,https_enforced,public,source}'
distribution=repos/jasonachkar/homebrew-lasa
inventory "$distribution" '{visibility,default_branch,security_and_analysis}'
inventory "$distribution/collaborators?per_page=100" '[.[]|{owner:(.login=="jasonachkar"),role_name}]'
inventory "$distribution/invitations?per_page=100" length
inventory "$distribution/keys?per_page=100" '[.[]|{read_only,verified}]'
inventory "$distribution/hooks?per_page=100" '[.[]|{active,events}]'
inventory "$distribution/actions/secrets" '[.secrets[].name]'
inventory "$distribution/actions/variables" '[.variables[].name]'
inventory "$distribution/actions/runners" '{total_count}'
inventory "$distribution/actions/workflows" '[.workflows[]|{name,path,state}]'
inventory "$distribution/actions/permissions/workflow" '.'
inventory "$distribution/rules/branches/main" '[.[]|{type,parameters}]'
inventory "$distribution/pages" '{build_type,status,https_enforced,public,source}'
inventory "$distribution/environments/github-pages/deployment-branch-policies" '[.branch_policies[]|{name,type}]'
inventory "$distribution/private-vulnerability-reporting" '{enabled}'
