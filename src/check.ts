import * as core from '@actions/core'
import * as github from '@actions/github'
import * as githubUtils from '@actions/github/lib/utils'
import * as retry from '@octokit/plugin-retry'

const retryingOctokit = githubUtils.GitHub.plugin(retry.retry)
const octo = new retryingOctokit(
  githubUtils.getOctokitOptions(core.getInput('repo-token', {required: true}))
)

export async function addCheck(
  body: string,
  checkName: string,
  sha: string,
  failed: boolean
): Promise<void> {
  const res = await octo.rest.checks.create({
    name: checkName,
    head_sha: sha,
    status: 'completed',
    conclusion: failed ? 'failure' : 'success',
    output: {
      title: checkName,
      summary: body
    },
    ...github.context.repo
  })

  core.debug(`Created check with id: ${res.data.id} url: ${res.data.url}`)
}
