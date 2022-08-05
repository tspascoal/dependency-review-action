import * as core from '@actions/core'
import * as github from '@actions/github'
import * as githubUtils from '@actions/github/lib/utils'
import * as retry from '@octokit/plugin-retry'
import {ConfigurationOptions, Changes, Change} from './schemas'

const retryingOctokit = githubUtils.GitHub.plugin(retry.retry)
const octo = new retryingOctokit(
  githubUtils.getOctokitOptions(core.getInput('repo-token', {required: true}))
)

let checkIdVulnerability: number
let checkIdLicense: number

export async function initChecks(
  sha: string,
  config: ConfigurationOptions
): Promise<void> {
  checkIdVulnerability = await createCheck(
    config.check_name_vulnerability || 'Dependency Review Vulnerabilities',
    sha
  )
  checkIdLicense = await createCheck(
    config.check_name_vulnerability || 'Dependency Review Licenses',
    sha
  )
}

export async function createLicensesCheck(
  licenseErrors: Change[],
  unknownLicensesErrors: Change[],
  failed: boolean,
  config: ConfigurationOptions
): Promise<void> {
  let body = ''

  if (licenseErrors.length > 0) {
    const manifests = getManifests(licenseErrors)

    core.debug(`found ${manifests.entries.length} manifests for licenses`)

    if (config.allow_licenses && config.allow_licenses.length > 0) {
      body += `\n> **Allowed Licenses**: ${config.allow_licenses.join(', ')}\n`
    }
    if (config.deny_licenses && config.deny_licenses.length > 0) {
      body += `\n> **Denied Licenses**: ${config.deny_licenses.join(', ')}\n`
    }

    body += `\n## Incompatible Licenses`

    for (const manifest of manifests) {
      body += `\n ### _${manifest}_\n|Package|Version|License|\n|---|---:|---|`

      for (const change of licenseErrors.filter(
        pkg => pkg.manifest === manifest
      )) {
        body += `\n|${renderUrl(change.source_repository_url, change.name)}|${
          change.version
        }|${change.license}|`
      }
    }
  }

  core.info(`found ${unknownLicensesErrors.length} unknown licenses`)

  if (unknownLicensesErrors.length > 0) {
    const manifests = getManifests(unknownLicensesErrors)

    core.debug(
      `found ${manifests.entries.length} manifests for unknown licenses`
    )

    body += `\n## Unknown Licenses\n`

    for (const manifest of manifests) {
      body += `\n ### Manifest _${manifest}_:\n|Package|Version|\n|---|---:|`

      for (const change of unknownLicensesErrors.filter(
        pkg => pkg.manifest === manifest
      )) {
        body += `\n|${renderUrl(change.source_repository_url, change.name)}|${
          change.version
        }|${change.license}|`
      }
    }
  }

  await updateCheck(checkIdLicense, 'Dependency Review', body, failed)
}

export async function createVulnerabilitiesCheck(
  addedPackages: Changes,
  failed: boolean,
  severity: string | undefined
): Promise<void> {
  const manifests = getManifests(addedPackages)

  let body = `## Dependency Review\nWe found ${addedPackages.length} vulnerabilities`

  core.debug(`found ${manifests.entries.length} manifests`)

  if (addedPackages.length > 0) {
    body += `\n## Vulnerabilities`
    body += severity
      ? `\n> Vulnerabilities where filtered by **${severity}** severity.\n`
      : ''
  }

  for (const manifest of manifests) {
    body += `\n### _${manifest}_\n|Package|Version|Vulnerability|Severity|\n|---|---:|---|---|`

    for (const change of addedPackages.filter(
      pkg => pkg.manifest === manifest
    )) {
      let previous_package = ''
      let previous_version = ''
      for (const vuln of change.vulnerabilities) {
        const sameAsPrevious =
          previous_package === change.name &&
          previous_version === change.version

        if (!sameAsPrevious) {
          body += `\n| ${renderUrl(
            change.source_repository_url,
            change.name
          )} | ${change.version}|`
        } else {
          body += '\n|||'
        }
        body += `${renderUrl(vuln.advisory_url, vuln.advisory_summary)} | ${
          vuln.severity
        } |`

        previous_package = change.name
        previous_version = change.version
      }
    }
  }

  await updateCheck(checkIdVulnerability, 'Dependency Review', body, failed)
}

function renderUrl(url: string | null, text: string): string {
  if (url) {
    return `[${text}](${url})`
  } else {
    return text
  }
}

function getManifests(changes: Changes): Set<string> {
  return new Set(changes.flatMap(c => c.manifest))
}

async function createCheck(checkName: string, sha: string): Promise<number> {
  core.debug(`creating check ${checkName} in progress`)
  const res = await octo.rest.checks.create({
    name: checkName,
    head_sha: sha,
    status: 'in_progress',
    ...github.context.repo
  })

  core.debug(`Created check with id: ${res.data.id} url: ${res.data.url}`)

  return res.data.id
}

async function updateCheck(
  id: number,
  title: string,
  body: string,
  failed: boolean
): Promise<void> {
  const res = await octo.rest.checks.create({
    id,
    status: 'completed',
    conclusion: failed ? 'failure' : 'success',
    output: {
      title,
      summary: body
    }
  })

  core.debug(`Created check with id: ${res.data.id} url: ${res.data.url}`)
}
